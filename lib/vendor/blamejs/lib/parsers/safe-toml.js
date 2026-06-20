"use strict";
/**
 * Security-focused TOML 1.0 parser.
 *
 * Implements TOML 1.0 (toml.io/en/v1.0.0) with the same defaults the
 * framework's other parsers apply:
 *
 *   - Size + depth + element-count limits (DoS prevention)
 *   - BOM stripping
 *   - Prototype-pollution rejection (__proto__ / constructor / prototype
 *     forbidden as bare keys, quoted keys, or dotted-key path segments)
 *   - Strict same-key redefinition rules per TOML spec (silent overwrite
 *     would mask config errors operators DO want surfaced)
 *
 * Output shape:
 *   - Strings: JS string (escape-decoded for basic/multi-line basic;
 *     verbatim for literal/multi-line literal)
 *   - Integers: JS Number when |n| <= Number.MAX_SAFE_INTEGER; throws
 *     toml/integer-overflow otherwise (operators get a clear failure
 *     instead of silent precision loss). Operators who legitimately
 *     need 64-bit integers should encode them as quoted strings.
 *   - Floats: JS Number; nan / inf / -inf preserved as JS NaN / Infinity
 *   - Booleans: true / false
 *   - Offset Date-Time: JS Date
 *   - Local Date-Time / Local Date / Local Time: ISO-formatted string
 *     (no implicit offset assumption)
 *   - Arrays: JS arrays
 *   - Tables / inline tables: plain JS objects
 *
 * What is REJECTED:
 *   - Same-key reassignment inside any table
 *   - Inline-table mutation (`x = { a = 1 }\nx.b = 2` is an error)
 *   - Defining a table whose name collides with an existing key
 *   - __proto__ / constructor / prototype as key names anywhere
 *   - Unterminated strings, arrays, or inline tables
 *
 * Public API:
 *   toml.parse(input, opts?)            object | throws SafeTomlError
 *   toml.SafeTomlError                  error class
 *
 * Defaults:
 *   maxBytes:  1 MiB
 *   maxDepth:  100
 *   maxKeys:   50000
 */

var C = require("../constants");
var pick = require("../pick");
var boundedMap = require("../bounded-map");
var codepointClass = require("../codepoint-class");
var numericBounds = require("../numeric-bounds");
var safeBuffer = require("../safe-buffer");
var { FrameworkError } = require("../framework-error");

class SafeTomlError extends FrameworkError {
  constructor(message, code, line, col) {
    super(line != null ? message + " at line " + line + ":" + col : message);
    this.name = "SafeTomlError";
    this.code = code || "toml/invalid";
    this.line = line == null ? null : line;
    this.col = col == null ? null : col;
    this.isSafeTomlError = true;
  }
}

// parseInt radices and TOML radix-prefix tokens — naming these constants
// keeps the literal `8` / `16` byte-shaped numbers off the call sites.
var RADIX_BIN     = 0x2;
var RADIX_OCTAL   = 0x8;
var RADIX_HEX     = 0x10;

// Date-time literal character widths (per TOML / RFC 3339).
var TIME_CHARS    = 0x8;    // "HH:MM:SS"
var OFFSET_CHARS  = 0x6;    // "+HH:MM"

var DEFAULTS = {
  maxBytes: C.BYTES.mib(1),
  maxDepth: 100,
  maxKeys:  50_000,
};


function parse(input, opts) {
  opts = opts || {};
  // Validate operator-supplied numeric opts via lib/numeric-bounds —
  // Infinity / NaN / negative / non-integer all bypass the `> 0` shape
  // and silently lift the DoS cap they were meant to enforce.
  if (opts.maxBytes !== undefined && !numericBounds.isPositiveFiniteInt(opts.maxBytes)) {
    throw new SafeTomlError("toml.parse: maxBytes must be a positive finite integer; got " +
      numericBounds.shape(opts.maxBytes), "toml/bad-opt");
  }
  if (opts.maxDepth !== undefined && !numericBounds.isPositiveFiniteInt(opts.maxDepth)) {
    throw new SafeTomlError("toml.parse: maxDepth must be a positive finite integer; got " +
      numericBounds.shape(opts.maxDepth), "toml/bad-opt");
  }
  if (opts.maxKeys !== undefined && !numericBounds.isPositiveFiniteInt(opts.maxKeys)) {
    throw new SafeTomlError("toml.parse: maxKeys must be a positive finite integer; got " +
      numericBounds.shape(opts.maxKeys), "toml/bad-opt");
  }
  var maxBytes = opts.maxBytes !== undefined
    ? Math.min(opts.maxBytes, C.BYTES.mib(64))
    : DEFAULTS.maxBytes;
  var maxDepth = opts.maxDepth !== undefined
    ? Math.min(opts.maxDepth, 1_000)
    : DEFAULTS.maxDepth;
  var maxKeys = opts.maxKeys !== undefined
    ? Math.min(opts.maxKeys, 1_000_000)
    : DEFAULTS.maxKeys;

  input = safeBuffer.normalizeText(input, {
    maxBytes:   maxBytes,
    errorClass: SafeTomlError,
    typeCode:   "toml/wrong-input-type",
    sizeCode:   "toml/too-large",
  });

  var pos = 0;
  var line = 1;
  var col = 1;
  var len = input.length;
  var root = Object.create(null);
  var definedTables = new Set();   // tables created by an explicit [a.b] header
  var inlineTablesSet = new WeakSet();
  var keyCount = 0;
  var current = root;

  function _err(msg, code) {
    return new SafeTomlError(msg, code || "toml/invalid", line, col);
  }

  function _bumpKeys() {
    keyCount += 1;
    if (keyCount > maxKeys) throw _err("input exceeds maxKeys", "toml/too-many-keys");
  }

  function _advance(n) {
    n = n == null ? 1 : n;
    for (var i = 0; i < n; i++) {
      if (pos >= len) return;
      if (input.charCodeAt(pos) === 0x0A) { line += 1; col = 1; }
      else col += 1;
      pos += 1;
    }
  }

  function _eof() { return pos >= len; }
  function _peek(off) { return input.charAt(pos + (off || 0)); }
  function _peekCode(off) { return input.charCodeAt(pos + (off || 0)); }

  function _skipSpacesAndTabs() {
    while (!_eof()) {
      var c = _peekCode();
      if (c === 0x20 || c === 0x09) _advance();
      else break;
    }
  }

  function _skipNewline() {
    if (_peek() === "\r" && _peek(1) === "\n") _advance(2);
    else if (_peek() === "\n") _advance(1);
    else throw _err("expected newline", "toml/expected-newline");
  }

  function _skipCommentAndNewline() {
    if (_peek() === "#") {
      while (!_eof() && _peekCode() !== 0x0A) _advance();
    }
    if (_eof()) return;
    _skipNewline();
  }

  function _markInlineTable(obj) { inlineTablesSet.add(obj); }
  function _isInlineTable(obj)   { return inlineTablesSet.has(obj); }

  // ---- Key parsing ----

  function _parseBareKey() {
    var start = pos;
    while (!_eof()) {
      var c = _peekCode();
      var ok =
        (c >= 0x41 && c <= 0x5A) ||  // A-Z
        (c >= 0x61 && c <= 0x7A) ||  // a-z
        (c >= 0x30 && c <= 0x39) ||  // 0-9
        c === 0x5F || c === 0x2D;    // _ -
      if (!ok) break;
      _advance();
    }
    if (pos === start) throw _err("expected key", "toml/expected-key");
    return input.substring(start, pos);
  }

  function _parseQuotedKey() {
    var quote = _peek();
    var basic = (quote === '"');
    _advance();
    var start = pos;
    var out = "";
    while (!_eof()) {
      var c = _peek();
      if (c === quote) {
        if (!basic) out = input.substring(start, pos);
        _advance();
        return out;
      }
      if (c === "\n") throw _err("newline in quoted key", "toml/bad-key");
      if (basic && c === "\\") {
        out += input.substring(start, pos);
        _advance();
        out += _decodeEscape();
        start = pos;
      } else {
        _advance();
      }
    }
    throw _err("unterminated quoted key", "toml/bad-key");
  }

  function _parseSingleKeySegment() {
    var c = _peek();
    if (c === '"' || c === "'") return _parseQuotedKey();
    return _parseBareKey();
  }

  function _parseDottedKey() {
    var segments = [_parseSingleKeySegment()];
    if (pick.isPoisonedKey(segments[0])) {
      throw _err("forbidden key '" + segments[0] + "'", "toml/poisoned-key");
    }
    while (true) {
      _skipSpacesAndTabs();
      if (_peek() !== ".") return segments;
      _advance();
      _skipSpacesAndTabs();
      var seg = _parseSingleKeySegment();
      if (pick.isPoisonedKey(seg)) {
        throw _err("forbidden key '" + seg + "'", "toml/poisoned-key");
      }
      segments.push(seg);
      // Cap dotted-key depth at maxDepth — same bound as `_parseValue`.
      // Without this, a table header `[a.b.c.d…]` with thousands of
      // segments builds a tree deep enough to stack-overflow the
      // post-parse `_normalize` walker (which is recursive). The check
      // sits at +1 over depth so a path of exactly maxDepth segments is
      // still accepted (matches the inclusive bound in _parseValue).
      if (segments.length > maxDepth) {
        throw _err("dotted-key path exceeds maxDepth (" + maxDepth + ")", "toml/too-deep");
      }
    }
  }

  // ---- Value parsing ----

  function _decodeEscape() {
    var c = _peek();
    _advance();
    switch (c) {
      case '"':  return '"';
      case '\\': return "\\";
      case "/":  return "/";
      case "b":  return "\b";
      case "f":  return "\f";
      case "n":  return "\n";
      case "r":  return "\r";
      case "t":  return "\t";
      case "u": {
        var hex = input.substring(pos, pos + 4);
        if (!safeBuffer.isHex(hex, 4)) {
          throw _err("bad \\u escape", "toml/bad-escape");
        }
        _advance(4);
        return String.fromCharCode(parseInt(hex, RADIX_HEX));
      }
      case "U": {
        var hexLen = 0x8;
        var hex8 = input.substring(pos, pos + hexLen);
        if (hex8.length < hexLen || !/^[0-9a-fA-F]{8}$/.test(hex8)) {
          throw _err("bad \\U escape", "toml/bad-escape");
        }
        _advance(hexLen);
        var code = parseInt(hex8, RADIX_HEX);
        if (code > 0x10FFFF) throw _err("\\U code point > U+10FFFF", "toml/bad-escape");
        return String.fromCodePoint(code);
      }
      default:
        throw _err("unknown escape '\\" + c + "'", "toml/bad-escape");
    }
  }

  function _parseBasicString() {
    _advance();
    var start = pos;
    var out = "";
    while (!_eof()) {
      var c = _peek();
      if (c === '"') {
        out += input.substring(start, pos);
        _advance();
        return out;
      }
      if (c === "\n") throw _err("newline in basic string (use triple-quote for multi-line)", "toml/bad-string");
      if (c === "\\") {
        out += input.substring(start, pos);
        _advance();
        out += _decodeEscape();
        start = pos;
        continue;
      }
      var cc = _peekCode();
      if (codepointClass.isForbiddenControlChar(cc)) {                                                // C0 (except TAB) + DEL refusal
        throw _err("unescaped control char in string", "toml/bad-string");
      }
      _advance();
    }
    throw _err("unterminated basic string", "toml/unterminated-string");
  }

  function _parseMultilineBasicString() {
    _advance(3);
    if (_peek() === "\n") _advance(1);
    else if (_peek() === "\r" && _peek(1) === "\n") _advance(2);
    var start = pos;
    var out = "";
    while (!_eof()) {
      if (_peek() === '"' && _peek(1) === '"' && _peek(2) === '"') {
        out += input.substring(start, pos);
        _advance(3);
        var trailing = 0;
        while (trailing < 2 && _peek() === '"') { out += '"'; _advance(); trailing += 1; }
        return out;
      }
      var c = _peek();
      if (c === "\\") {
        out += input.substring(start, pos);
        _advance();
        if (_peek() === "\n" || (_peek() === "\r" && _peek(1) === "\n")) {
          if (_peek() === "\r") _advance();
          _advance();
          _skipSpacesAndTabs();
          while (_peek() === "\n" || (_peek() === "\r" && _peek(1) === "\n")) {
            if (_peek() === "\r") _advance();
            _advance();
            _skipSpacesAndTabs();
          }
          start = pos;
          continue;
        }
        out += _decodeEscape();
        start = pos;
        continue;
      }
      _advance();
    }
    throw _err("unterminated multi-line basic string", "toml/unterminated-string");
  }

  function _parseLiteralString() {
    _advance();
    var start = pos;
    while (!_eof()) {
      if (_peek() === "'") {
        var s = input.substring(start, pos);
        _advance();
        return s;
      }
      if (_peek() === "\n") throw _err("newline in literal string", "toml/bad-string");
      _advance();
    }
    throw _err("unterminated literal string", "toml/unterminated-string");
  }

  function _parseMultilineLiteralString() {
    _advance(3);
    if (_peek() === "\n") _advance(1);
    else if (_peek() === "\r" && _peek(1) === "\n") _advance(2);
    var start = pos;
    while (!_eof()) {
      if (_peek() === "'" && _peek(1) === "'" && _peek(2) === "'") {
        var s = input.substring(start, pos);
        _advance(3);
        var trailing = 0;
        while (trailing < 2 && _peek() === "'") { s += "'"; _advance(); trailing += 1; }
        return s;
      }
      _advance();
    }
    throw _err("unterminated multi-line literal string", "toml/unterminated-string");
  }

  // Date-time, date-only, or time-only.
  // Returns { kind, value } where for "offset" value is a JS Date and for
  // the others value is the canonical ISO string. Returns null if the
  // current position doesn't start a date-time literal.
  function _tryParseDateTime() {
    // Date-time form: YYYY-MM-DD followed by 'T'/' ' followed by time
    if (pos + 10 <= len && /^\d{4}-\d{2}-\d{2}/.test(input.substr(pos, 10))) {
      var sep = _peek(10);
      if (sep === "T" || sep === "t" || sep === " ") {
        // Look ahead for time portion (HH:MM:SS = 8 chars)
        var timeStart = pos + 11;
        var timeChars = TIME_CHARS;
        if (/^\d{2}:\d{2}:\d{2}/.test(input.substr(timeStart, timeChars))) {
          var datePart = input.substr(pos, 10);
          var timeEnd = timeStart + timeChars;
          // Optional fractional
          if (_peek(timeEnd - pos) === ".") {
            timeEnd += 1;
            while (timeEnd < len && /\d/.test(input.charAt(timeEnd))) timeEnd += 1;
          }
          var timePart = input.substring(timeStart, timeEnd);
          // Optional offset
          var offsetStr = "";
          var nextChar = input.charAt(timeEnd);
          if (nextChar === "Z" || nextChar === "z") { offsetStr = "Z"; timeEnd += 1; }
          else if (nextChar === "+" || nextChar === "-") {
            // Expect ±HH:MM (6 chars)
            var offsetChars = OFFSET_CHARS;
            var off = input.substr(timeEnd, offsetChars);
            if (/^[+-]\d{2}:\d{2}$/.test(off)) {
              offsetStr = off;
              timeEnd += offsetChars;
            }
          }
          _advance(timeEnd - pos);
          if (offsetStr) {
            var iso = datePart + "T" + timePart + offsetStr;
            var d = new Date(iso);
            if (isNaN(d.getTime())) throw _err("invalid offset date-time", "toml/bad-datetime");
            return { kind: "offset", value: d };
          }
          return { kind: "local-dt", value: datePart + "T" + timePart };
        }
        // 'T' / ' ' followed by non-time → fall through to date-only check below
      }
      // Date-only — but only if followed by something OTHER than digit/colon
      var after = _peek(10);
      if (!after || !/[0-9:.]/.test(after)) {
        var ds = input.substr(pos, 10);
        _advance(10);
        return { kind: "local-date", value: ds };
      }
    }
    // Time-only: HH:MM:SS (8 chars)
    var timeOnlyChars = TIME_CHARS;
    if (pos + timeOnlyChars <= len && /^\d{2}:\d{2}:\d{2}/.test(input.substr(pos, timeOnlyChars))) {
      var teEnd = pos + timeOnlyChars;
      if (input.charAt(teEnd) === ".") {
        teEnd += 1;
        while (teEnd < len && /\d/.test(input.charAt(teEnd))) teEnd += 1;
      }
      var ts = input.substring(pos, teEnd);
      _advance(teEnd - pos);
      return { kind: "local-time", value: ts };
    }
    return null;
  }

  function _parseNumber(firstChar) {
    var startPos = pos;
    var startLine = line;
    var startCol = col;

    // Special floats: inf, nan with optional sign
    if (firstChar === "+" || firstChar === "-") {
      var rest = input.substring(pos + 1, pos + 4);
      if (rest === "inf") { _advance(4); return firstChar === "-" ? -Infinity : Infinity; }
      if (rest === "nan") { _advance(4); return NaN; }
    } else if (firstChar === "i" || firstChar === "n") {
      var w = input.substring(pos, pos + 3);
      if (w === "inf") { _advance(3); return Infinity; }
      if (w === "nan") { _advance(3); return NaN; }
    }

    var sign = 1;
    if (_peek() === "+") _advance();
    else if (_peek() === "-") { sign = -1; _advance(); }

    if (_peek() === "0") {
      var prefix = _peek(1);
      if (prefix === "x" || prefix === "o" || prefix === "b") {
        if (sign !== 1) throw _err("sign not allowed on hex/oct/bin literal", "toml/bad-number");
        _advance(2);
        var radix = prefix === "x" ? RADIX_HEX : prefix === "o" ? RADIX_OCTAL : RADIX_BIN;
        var digitsStart = pos;
        while (!_eof()) {
          var ch = _peek();
          if (ch === "_") { _advance(); continue; }
          if (radix === RADIX_HEX   && /[0-9a-fA-F]/.test(ch)) { _advance(); continue; }
          if (radix === RADIX_OCTAL && /[0-7]/.test(ch))       { _advance(); continue; }
          if (radix === RADIX_BIN   && /[01]/.test(ch))        { _advance(); continue; }
          break;
        }
        var digits = input.substring(digitsStart, pos).replace(/_/g, "");
        if (digits.length === 0) throw _err("expected digits after radix prefix", "toml/bad-number");
        var n = parseInt(digits, radix);
        if (!Number.isSafeInteger(n)) {
          throw new SafeTomlError("integer overflow (use a quoted string for 64-bit values)",
            "toml/integer-overflow", startLine, startCol);
        }
        return n;
      }
    }

    var hasDot = false;
    var hasExp = false;
    while (!_eof()) {
      var ch2 = _peek();
      if (ch2 === "_") { _advance(); continue; }
      if (ch2 >= "0" && ch2 <= "9") { _advance(); continue; }
      if (ch2 === "." && !hasDot && !hasExp) { hasDot = true; _advance(); continue; }
      if ((ch2 === "e" || ch2 === "E") && !hasExp) {
        hasExp = true;
        _advance();
        if (_peek() === "+" || _peek() === "-") _advance();
        continue;
      }
      break;
    }
    var raw = input.substring(startPos, pos).replace(/_/g, "");
    if (raw === "" || raw === "-" || raw === "+") {
      throw new SafeTomlError("invalid number", "toml/bad-number", startLine, startCol);
    }
    if (hasDot || hasExp) {
      var f = parseFloat(raw);
      if (isNaN(f)) {
        throw new SafeTomlError("invalid float", "toml/bad-number", startLine, startCol);
      }
      return f;
    }
    var i = parseInt(raw, 10);
    if (!Number.isSafeInteger(i)) {
      throw new SafeTomlError("integer overflow (use a quoted string for 64-bit values)",
        "toml/integer-overflow", startLine, startCol);
    }
    return i;
  }

  function _parseValue(depth) {
    if (depth > maxDepth) throw _err("input exceeds maxDepth", "toml/too-deep");
    _skipSpacesAndTabs();
    if (_eof()) throw _err("expected value, got EOF", "toml/expected-value");

    var c = _peek();

    if (c === '"' && _peek(1) === '"' && _peek(2) === '"') return _parseMultilineBasicString();
    if (c === "'" && _peek(1) === "'" && _peek(2) === "'") return _parseMultilineLiteralString();
    if (c === '"') return _parseBasicString();
    if (c === "'") return _parseLiteralString();
    if (c === "[") return _parseArray(depth + 1);
    if (c === "{") return _parseInlineTable(depth + 1);

    if (input.substr(pos, 4) === "true" && !/[A-Za-z0-9_]/.test(input.charAt(pos + 4) || "")) {
      _advance(4); return true;
    }
    if (input.substr(pos, 5) === "false" && !/[A-Za-z0-9_]/.test(input.charAt(pos + 5) || "")) {
      _advance(5); return false;
    }

    var dt = _tryParseDateTime();
    if (dt !== null) return dt.value;

    if (/[0-9+\-i n]/.test(c)) return _parseNumber(c);

    throw _err("unexpected character '" + c + "'", "toml/expected-value");
  }

  function _parseArray(depth) {
    if (depth > maxDepth) throw _err("input exceeds maxDepth", "toml/too-deep");
    _advance();
    var arr = [];
    while (true) {
      _skipArrayWhitespace();
      if (_peek() === "]") { _advance(); return arr; }
      arr.push(_parseValue(depth));
      _skipArrayWhitespace();
      if (_peek() === ",") { _advance(); continue; }
      _skipArrayWhitespace();
      if (_peek() === "]") { _advance(); return arr; }
      throw _err("expected ',' or ']' in array", "toml/bad-array");
    }
  }

  function _skipArrayWhitespace() {
    while (!_eof()) {
      var c = _peek();
      if (c === " " || c === "\t" || c === "\n" || c === "\r") { _advance(); continue; }
      if (c === "#") {
        while (!_eof() && _peekCode() !== 0x0A) _advance();
        continue;
      }
      break;
    }
  }

  function _parseInlineTable(depth) {
    if (depth > maxDepth) throw _err("input exceeds maxDepth", "toml/too-deep");
    _advance();
    var tbl = Object.create(null);
    _markInlineTable(tbl);
    _skipSpacesAndTabs();
    if (_peek() === "}") { _advance(); return tbl; }
    while (true) {
      _skipSpacesAndTabs();
      var pathSegs = _parseDottedKey();
      _skipSpacesAndTabs();
      if (_peek() !== "=") throw _err("expected '=' in inline table", "toml/bad-inline-table");
      _advance();
      _skipSpacesAndTabs();
      var v = _parseValue(depth);
      _bumpKeys();
      _setNested(tbl, pathSegs, v);
      _skipSpacesAndTabs();
      if (_peek() === ",") {
        _advance();
        if (_peek() === "}") throw _err("trailing comma in inline table", "toml/bad-inline-table");
        continue;
      }
      if (_peek() === "}") { _advance(); return tbl; }
      throw _err("expected ',' or '}' in inline table", "toml/bad-inline-table");
    }
  }

  function _setNested(table, segments, value) {
    var t = table;
    for (var i = 0; i < segments.length - 1; i++) {
      var seg = segments[i];
      if (pick.isPoisonedKey(seg)) throw _err("forbidden key segment", "toml/poisoned-key");
      if (Object.prototype.hasOwnProperty.call(t, seg)) {
        var sub = t[seg];
        if (sub == null || typeof sub !== "object" || Array.isArray(sub)) {
          throw _err("cannot redefine '" + seg + "' as a sub-table", "toml/redefine");
        }
        if (_isInlineTable(sub)) {
          throw _err("cannot extend inline table '" + seg + "'", "toml/inline-table-mutated");
        }
        t = sub;
      } else {
        var fresh = Object.create(null);
        t[seg] = fresh;
        t = fresh;
      }
    }
    var last = segments[segments.length - 1];
    if (pick.isPoisonedKey(last)) throw _err("forbidden key segment", "toml/poisoned-key");
    if (Object.prototype.hasOwnProperty.call(t, last)) {
      throw _err("duplicate key '" + last + "'", "toml/duplicate-key");
    }
    t[last] = value;
  }

  function _parseTableHeader() {
    var isAoT = _peek(1) === "[";
    _advance(isAoT ? 2 : 1);
    _skipSpacesAndTabs();
    var segments = _parseDottedKey();
    _skipSpacesAndTabs();
    if (isAoT) {
      if (_peek() !== "]" || _peek(1) !== "]") throw _err("expected ']]'", "toml/bad-table-header");
      _advance(2);
    } else {
      if (_peek() !== "]") throw _err("expected ']'", "toml/bad-table-header");
      _advance();
    }
    _skipSpacesAndTabs();
    _skipCommentAndNewline();

    var t = root;
    for (var i = 0; i < segments.length; i++) {
      var seg = segments[i];
      if (pick.isPoisonedKey(seg)) throw _err("forbidden key segment", "toml/poisoned-key");
      var isLast = (i === segments.length - 1);
      if (Object.prototype.hasOwnProperty.call(t, seg)) {
        var sub = t[seg];
        if (Array.isArray(sub)) {
          if (isLast && isAoT) {
            var fresh = Object.create(null);
            sub.push(fresh);
            current = fresh;
            return;
          }
          if (isLast && !isAoT) {
            throw _err("table '" + seg + "' previously defined as array of tables",
              "toml/redefine");
          }
          t = sub[sub.length - 1];
          // The array's last element must itself be a table to descend
          // into. A plain VALUE array (e.g. `a = [3]` then `[a.s]`) has a
          // scalar last element — descending would set a property on a
          // number and throw a raw TypeError; refuse it cleanly instead.
          if (t === null || typeof t !== "object" || Array.isArray(t)) {
            throw _err("cannot descend into '" + seg +
              "' — it is a value array, not an array of tables", "toml/redefine");
          }
          continue;
        }
        if (typeof sub !== "object" || sub === null) {
          throw _err("cannot redefine '" + seg + "' as a sub-table", "toml/redefine");
        }
        if (_isInlineTable(sub)) {
          throw _err("cannot extend inline table '" + seg + "'", "toml/inline-table-mutated");
        }
        if (isLast && !isAoT) {
          var fullPath = segments.slice(0, i + 1).join(".");
          boundedMap.requireAbsentMember(definedTables, fullPath, function () {
            throw _err("table '" + fullPath + "' defined twice", "toml/redefine");
          });
          definedTables.add(fullPath);
          current = sub;
          return;
        }
        if (isLast && isAoT) {
          throw _err("'" + seg + "' was a table; cannot redefine as array of tables",
            "toml/redefine");
        }
        t = sub;
      } else {
        if (isLast && isAoT) {
          var arr = [];
          t[seg] = arr;
          var freshT = Object.create(null);
          arr.push(freshT);
          current = freshT;
          return;
        }
        if (isLast && !isAoT) {
          var freshT2 = Object.create(null);
          t[seg] = freshT2;
          var fullPath2 = segments.slice(0, i + 1).join(".");
          definedTables.add(fullPath2);
          current = freshT2;
          return;
        }
        var freshParent = Object.create(null);
        t[seg] = freshParent;
        t = freshParent;
      }
    }
  }

  function _parseKeyValueLine() {
    var pathSegs = _parseDottedKey();
    _skipSpacesAndTabs();
    if (_peek() !== "=") throw _err("expected '=' after key", "toml/bad-kv");
    _advance();
    _skipSpacesAndTabs();
    var v = _parseValue(1);
    _bumpKeys();
    _setNested(current, pathSegs, v);
    _skipSpacesAndTabs();
    _skipCommentAndNewline();
  }

  while (!_eof()) {
    _skipSpacesAndTabs();
    if (_eof()) break;
    var c = _peek();
    if (c === "#") {
      while (!_eof() && _peekCode() !== 0x0A) _advance();
      if (!_eof()) _skipNewline();
      continue;
    }
    if (c === "\n" || (c === "\r" && _peek(1) === "\n")) {
      _skipNewline();
      continue;
    }
    if (c === "[") {
      _parseTableHeader();
      continue;
    }
    _parseKeyValueLine();
  }

  // Strip null-prototype objects to plain {}-prototype for the operator;
  // null-prototype is only needed during build to block prototype pollution.
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
  return _normalize(root);
}

module.exports = {
  parse:         parse,
  SafeTomlError: SafeTomlError,
};
