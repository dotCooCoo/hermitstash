// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var C = require("../constants");
var pick = require("../pick");
var boundedMap = require("../bounded-map");
var numericBounds = require("../numeric-bounds");
var safeBuffer = require("../safe-buffer");
var codepointClass = require("../codepoint-class");
var yamlLex = require("../yaml-lex");
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

var RADIX_OCTAL = 0x8;
var RADIX_HEX   = 0x10;

var MAX_SCALAR_BYTES = C.BYTES.kib(64);

var DEFAULTS = {
  maxBytes: C.BYTES.mib(1),
  maxDepth: 100,
  maxKeys:  50_000,
};


var NULL_TOKENS = { "": 1, "null": 1, "Null": 1, "NULL": 1, "~": 1 };
var BOOL_TRUE   = { "true": 1, "True": 1, "TRUE": 1 };
var BOOL_FALSE  = { "false": 1, "False": 1, "FALSE": 1 };
var INF_TOKENS  = { ".inf": 1, ".Inf": 1, ".INF": 1 };
var NAN_TOKENS  = { ".nan": 1, ".NaN": 1, ".NAN": 1 };
var OCTAL_DIGITS = "01234567";

function _isNull(s) { return Object.prototype.hasOwnProperty.call(NULL_TOKENS, s); }
function _isBool(s) {
  return Object.prototype.hasOwnProperty.call(BOOL_TRUE, s) ||
         Object.prototype.hasOwnProperty.call(BOOL_FALSE, s);
}

function _signOffset(s) { var c = s.charAt(0); return (c === "-" || c === "+") ? 1 : 0; }

function _isDecimalInt(s) {
  var i = _signOffset(s);
  var rest = s.slice(i);
  if (rest.length === 0) return false;
  if (rest === "0") return true;
  if (rest.charAt(0) === "0") return false;
  return codepointClass.isRunOf(rest, codepointClass.ASCII_DIGITS);
}

function _isPrefixedInt(s, marker, alphabet) {
  if (s.length < 3) return false;
  if (s.charAt(0) !== "0" || s.charAt(1) !== marker) return false;
  return codepointClass.isRunOf(s.slice(2), alphabet);
}
function _isOctalInt(s) { return _isPrefixedInt(s, "o", OCTAL_DIGITS); }
function _isHexInt(s)   { return _isPrefixedInt(s, "x", codepointClass.ASCII_HEX); }

function _isFloat(s) {
  var i = _signOffset(s);
  var n = s.length;
  if (s.charAt(i) === ".") {
    i += 1;
    var fracStart = i;
    while (i < n && codepointClass.ASCII_DIGITS.indexOf(s.charAt(i)) !== -1) i += 1;
    if (i === fracStart) return false;
  } else {
    var intStart = i;
    while (i < n && codepointClass.ASCII_DIGITS.indexOf(s.charAt(i)) !== -1) i += 1;
    if (i === intStart) return false;
    if (s.charAt(i) === ".") {
      i += 1;
      while (i < n && codepointClass.ASCII_DIGITS.indexOf(s.charAt(i)) !== -1) i += 1;
    }
  }
  if (i === n) return true;
  var e = s.charAt(i);
  if (e !== "e" && e !== "E") return false;
  i += 1;
  var expSign = s.charAt(i);
  if (expSign === "+" || expSign === "-") i += 1;
  if (i >= n) return false;
  return codepointClass.isRunOf(s.slice(i), codepointClass.ASCII_DIGITS);
}

function _isInfinity(s) {
  return Object.prototype.hasOwnProperty.call(INF_TOKENS, s.slice(_signOffset(s)));
}
function _isNotANumber(s) {
  return Object.prototype.hasOwnProperty.call(NAN_TOKENS, s);
}

function _isWhitespaceChar(ch) {
  return ch.length === 1 && codepointClass.inRanges(ch.charCodeAt(0), codepointClass.WHITESPACE_RANGES);
}

function _isLineTerminator(ch) {
  return ch === "\n" || ch === "\r" || ch === "\u2028" || ch === "\u2029";
}

function _isDocumentMarker(line, marker) {
  if (line.slice(0, marker.length) !== marker) return false;
  if (line.length === marker.length) return true;
  return _isWhitespaceChar(line.charAt(marker.length));
}

function _isBlockScalarHeader(content, allowComment) {
  var i = 0;
  var lead = content.charAt(0);
  if (lead !== "|" && lead !== ">") return false;
  i += 1;
  var sign = content.charAt(i);
  if (sign === "-" || sign === "+") i += 1;
  var digit = content.charAt(i);
  if (digit.length === 1 && codepointClass.ASCII_DIGITS.indexOf(digit) !== -1) i += 1;
  while (i < content.length && _isWhitespaceChar(content.charAt(i))) i += 1;
  if (i === content.length) return true;
  if (!allowComment) return false;
  if (content.charAt(i) !== "#") return false;
  var tail = content.slice(i);
  for (var t = 0; t < tail.length; t += 1) {
    if (_isLineTerminator(tail.charAt(t))) return false;
  }
  return true;
}

var _NAME_HEAD = codepointClass.ASCII_ALNUM + "_";

function _findAnchorOrAlias(text) {
  for (var i = 0; i < text.length; i += 1) {
    var ch = text.charAt(i);
    if (ch !== "&" && ch !== "*") continue;
    var atStart = i === 0;
    if (_NAME_HEAD.indexOf(text.charAt(i + 1)) === -1 || text.charAt(i + 1) === "") continue;
    return { index: atStart ? i : i - 1, sigil: ch };
  }
  return null;
}

function _findTag(text) {
  for (var i = 0; i < text.length; i += 1) {
    if (text.charAt(i) !== "!") continue;
    var atStart = i === 0;
    var after = text.charAt(i + 1) === "!" ? text.charAt(i + 2) : text.charAt(i + 1);
    if (after.length !== 1) continue;
    if (after !== "<" && codepointClass.ASCII_ALNUM.indexOf(after) === -1) continue;
    return { index: atStart ? i : i - 1 };
  }
  return null;
}

var _DIRECTIVE_NAMES = ["YAML", "TAG"];

function _findDirective(text) {
  for (var i = 0; i < text.length; i += 1) {
    if (text.charAt(i) !== "%") continue;
    var atStart = i === 0;
    if (!atStart && text.charAt(i - 1) !== "\n") continue;
    for (var d = 0; d < _DIRECTIVE_NAMES.length; d += 1) {
      var name = _DIRECTIVE_NAMES[d];
      if (text.slice(i + 1, i + 1 + name.length) !== name) continue;
      var next = text.charAt(i + 1 + name.length);
      if (next.length === 1 && (_NAME_HEAD.indexOf(next) !== -1)) continue;
      return { index: atStart ? i : i - 1, precededByNewline: !atStart };
    }
  }
  return null;
}

function _resolveScalar(s) {
  if (typeof s !== "string" || s.length > MAX_SCALAR_BYTES) return s;
  if (_isNull(s)) return null;
  if (_isBool(s)) return s.toLowerCase() === "true";
  if (_isDecimalInt(s)) {
    var n = parseInt(s, 10);
    if (Number.isSafeInteger(n)) return n;
    return s;
  }
  if (_isOctalInt(s)) {
    var oct = parseInt(s.substring(2), RADIX_OCTAL);
    if (Number.isSafeInteger(oct)) return oct;
    return s;
  }
  if (_isHexInt(s)) {
    var hex = parseInt(s.substring(2), RADIX_HEX);
    if (Number.isSafeInteger(hex)) return hex;
    return s;
  }
  if (_isInfinity(s)) return s.charAt(0) === "-" ? -Infinity : Infinity;
  if (_isNotANumber(s)) return NaN;
  if (_isFloat(s)) {
    var f = parseFloat(s);
    if (!isNaN(f)) return f;
  }
  return s;
}

function parse(input, opts) {
  opts = opts || {};
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

  _preValidate(input);

  input = codepointClass.splitLinesAny(input).join("\n");

  var rawLines = input.split("\n");
  var lines = [];
  for (var i = 0; i < rawLines.length; i++) {
    var raw = rawLines[i];
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

  var idx = 0;
  while (idx < lines.length && (lines[idx].isBlank || lines[idx].isComment)) idx += 1;
  if (idx < lines.length && _isDocumentMarker(lines[idx].content, "---")) idx += 1;
  for (var j = idx; j < lines.length; j++) {
    var c = lines[j].content;
    if (_isDocumentMarker(c, "---") || _isDocumentMarker(c, "...")) {
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

  function parseValueAtLine(startIdx, parentIndent, depth) {
    if (depth > maxDepth) {
      throw new SafeYamlError("input exceeds maxDepth", "yaml/too-deep",
        startIdx < lines.length ? lines[startIdx].lineNumber : null, 1);
    }

    var k = startIdx;
    while (k < lines.length && (lines[k].isBlank || lines[k].isComment)) k += 1;
    if (k >= lines.length) return { value: null, nextLine: lines.length };

    var firstLine = lines[k];
    if (firstLine.indent <= parentIndent) {
      return { value: null, nextLine: k };
    }

    var content = firstLine.content;
    var indent = firstLine.indent;

    if (content === "-" || content.startsWith("- ")) {
      return _parseBlockSequence(k, indent, depth);
    }

    if (content.charAt(0) === "{" || content.charAt(0) === "[") {
      return { value: _parseInlineValue(content, firstLine.lineNumber, indent), nextLine: k + 1 };
    }

    var keyRange = _scanKeyRange(content, firstLine.lineNumber, indent);
    if (keyRange) {
      return _parseBlockMapping(k, indent, depth);
    }

    if (_isBlockScalarHeader(content, true)) {
      return _parseBlockScalar(k, indent, content);
    }

    return _parseScalarOrFlow(k, indent);
  }

  function _scanKeyRange(content, lineNumber, indent) {
    var p = 0;
    var len = content.length;
    if (len === 0) return null;
    if (content.charAt(0) === "?") {
      throw new SafeYamlError("complex keys (`? key`) are not supported",
        "yaml/complex-key-banned", lineNumber, indent + 1);
    }
    if (content.charAt(0) === '"') {
      var i = 1;
      while (i < len) {
        var ch = content.charAt(i);
        if (ch === "\\") { i += 2; continue; }
        if (ch === '"') break;
        i += 1;
      }
      if (i >= len) return null;
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
        throw new SafeYamlError("unexpected indent", "yaml/bad-indent", ln.lineNumber, ln.indent + 1);
      }
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

      var afterColon = codepointClass.trimChars(
        ln.content.substring(keyRange.valueStart), " \t", { trailing: false });
      afterColon = _stripEolComment(afterColon);
      var value;
      if (afterColon.length > 0) {
        if (afterColon.charAt(0) === "|" || afterColon.charAt(0) === ">") {
          if (!_isBlockScalarHeader(afterColon, false)) {
            throw new SafeYamlError("malformed block scalar header",
              "yaml/bad-block-scalar", ln.lineNumber, ln.indent + 1);
          }
          var bs = _parseBlockScalar(k, indent, afterColon);
          value = bs.value;
          k = bs.nextLine;
          result[key] = value;
          continue;
        }
        value = _parseInlineValue(afterColon, ln.lineNumber, ln.indent + keyRange.valueStart);
        k += 1;
      } else {
        var nested = parseValueAtLine(k + 1, indent, depth + 1);
        value = nested.value;
        k = nested.nextLine;
      }
      result[key] = value;
    }
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

      var afterDash = ln.content === "-" ? "" : ln.content.substring(2);
      afterDash = _stripEolComment(afterDash);
      var item;
      if (afterDash.length === 0) {
        var nested = parseValueAtLine(k + 1, indent, depth + 1);
        item = nested.value;
        k = nested.nextLine;
      } else {
        var mapKey = _scanKeyRange(afterDash, ln.lineNumber, ln.indent + 2);
        if (mapKey) {
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
    var t = text;
    if (t.charAt(0) === "[" || t.charAt(0) === "{") {
      var fend = _parseFlowValue(t, 0, lineNumber, col, 0).nextPos;
      var afterFlow = codepointClass.trimRanges(
        t.slice(fend), codepointClass.WHITESPACE_RANGES, { trailing: false });
      if (afterFlow.length > 0 && afterFlow.charAt(0) !== "#") {
        throw new SafeYamlError("unexpected content after flow collection",
          "yaml/trailing-content", lineNumber, col);
      }
      return t.charAt(0) === "[" ? _parseFlowSequence(t, lineNumber, col, 0)
                                 : _parseFlowMapping(t, lineNumber, col, 0);
    }
    if (t.charAt(0) === '"') {
      var dq = _decodeDoubleQuoted(t, lineNumber, col);
      var afterDq = _trailingAfterQuoted(t, '"');
      if (afterDq.length > 0 &&
          codepointClass.trimRanges(afterDq, codepointClass.WHITESPACE_RANGES, { trailing: false }) !== "") {
        throw new SafeYamlError("unexpected content after quoted string",
          "yaml/trailing-content", lineNumber, col);
      }
      return dq;
    }
    if (t.charAt(0) === "'") {
      var sq = _decodeSingleQuoted(t, lineNumber, col);
      return sq;
    }
    return _resolveScalar(safeBuffer.stripTrailingHspace(t));
  }

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

  function _parseFlowSequence(text, lineNumber, col, depthIncoming) {
    var p = 1;
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
      if (key === "<<") {
        throw new SafeYamlError("merge key '<<' not supported (anchor-using feature)",
          "yaml/merge-key-banned", lineNumber, col + p);
      }
      if (Object.prototype.hasOwnProperty.call(result, key)) {
        throw new SafeYamlError("duplicate mapping key '" + key + "'",
          "yaml/duplicate-key", lineNumber, col + p);
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
            if (hex8.length !== 8 || !codepointClass.isRunOf(hex8, codepointClass.ASCII_HEX)) {
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
    for (var i = 1; i < text.length; i++) {
      if (text.charCodeAt(i) !== 0x23 ) continue;
      var prev = text.charCodeAt(i - 1);
      if (prev !== 0x20 && prev !== 0x09 && prev !== 0x0b && prev !== 0x0c && prev !== 0x0d) continue;
      var end = i;
      while (end > 0) {
        var c = text.charCodeAt(end - 1);
        if (c === 0x20 || c === 0x09 || c === 0x0b || c === 0x0c || c === 0x0d) end--;
        else break;
      }
      return safeBuffer.stripTrailingHspace(text.slice(0, end));
    }
    return safeBuffer.stripTrailingHspace(text);
  }

  function _parseBlockScalar(startIdx, parentIndent, headerContent) {
    var headerLine = lines[startIdx];
    var header = headerContent.trim();
    var style = header.charAt(0);
    var rest = header.substring(1);
    var chomp = "";
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
        break;
      }
    }

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

    var trailingBlanks = 0;
    while (contentLines.length > 0 && contentLines[contentLines.length - 1] === "") {
      contentLines.pop();
      trailingBlanks += 1;
    }

    var body;
    if (style === "|") {
      body = contentLines.join("\n");
      if (contentLines.length > 0) body += "\n";
    } else {
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
      body = codepointClass.trimRanges(body, [0x0A], { leading: false });
    } else if (chomp === "+") {
      body += "\n".repeat(trailingBlanks);
    } 

    return { value: body, nextLine: k };
  }

  function _parseScalarOrFlow(startIdx, indent) {
    var ln = lines[startIdx];
    var content = _stripEolComment(ln.content);
    var v = _parseInlineValue(content, ln.lineNumber, ln.indent + 1);
    return { value: v, nextLine: startIdx + 1 };
  }

  var top = parseValueAtLine(idx, -1, 1);

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

function _preValidate(input) {
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
    if (c === "#") {
      while (i < len && input.charAt(i) !== "\n") {
        safe += input.charAt(i);
        i += 1;
        col += 1;
      }
      continue;
    }
    if (c === '"' || c === "'") {
      var quote = c;
      var startLine = line;
      var startCol = col;
      safe += c;
      advance();
      while (i < len) {
        var ch = input.charAt(i);
        if (quote === '"' && ch === "\\" && i + 1 < len) {
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
        safe += (ch === "\n") ? "\n" : " ";
        advance();
      }
      if (i > len) {
        throw new SafeYamlError("unterminated quoted string",
          "yaml/unterminated-string", startLine, startCol);
      }
      continue;
    }
    safe += c;
    advance();
  }

  safe = yamlLex.maskNonStructural(input);

  var m = _findAnchorOrAlias(safe);
  if (m) {
    var lineCount = safe.substring(0, m.index).split("\n").length;
    throw new SafeYamlError(
      m.sigil === "&" ? "anchors are not supported" : "aliases are not supported",
      m.sigil === "&" ? "yaml/anchors-banned" : "yaml/aliases-banned",
      lineCount, 1
    );
  }

  var mt = _findTag(safe);
  if (mt) {
    var tagLine = safe.substring(0, mt.index).split("\n").length;
    throw new SafeYamlError("tags are not supported",
      "yaml/tags-banned", tagLine, 1);
  }

  var md = _findDirective(safe);
  if (md) {
    var dirLine = safe.substring(0, md.index).split("\n").length + (md.precededByNewline ? 1 : 0);
    throw new SafeYamlError("directives are not supported",
      "yaml/directives-banned", dirLine, 1);
  }
}

module.exports = {
  parse:          parse,
  SafeYamlError:  SafeYamlError,
};
