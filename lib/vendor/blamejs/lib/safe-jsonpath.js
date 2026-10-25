// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.safeJsonPath
 * @nav    Validation
 * @title  Safe JSON Path
 * @slug   safe-json-path
 *
 * @intro
 *   Checks the keys, pointers and path expressions that reach a JSON column
 *   or document store. A path is a query, so operator input in one is the same
 *   class of problem as operator input in SQL.
 *
 *   The checks refuse what a renderer or a store would read differently from
 *   how it looks: NUL and control characters, bidirectional overrides and
 *   zero-width characters, all of which let a key print as one thing and match
 *   another. Keys, pointer depth and expression length are bounded, so a path
 *   cannot become the denial of service.
 *
 *   A JSONPath filter expression is refused outright rather than sanitized.
 *   A filter carries predicate logic, and there is no reliable way to accept
 *   one built from operator input: the path is built at the call site with
 *   bound values instead.
 *
 * @card
 *   Validate JSON keys, pointers and path expressions, refusing control and
 *   bidi characters, unbounded depth, and JSONPath filter expressions
 *   outright.
 */

var canonicalJson = require("./canonical-json");
var codepointClass = require("./codepoint-class");
var C = require("./constants");
var safeBuffer = require("./safe-buffer");
var { defineClass, FrameworkError } = require("./framework-error");

var SafeJsonPathError = defineClass("SafeJsonPathError", { alwaysPermanent: true });
var _err = SafeJsonPathError.factory;
void FrameworkError;

var MAX_KEY_BYTES        = C.BYTES.kib(1);
var MAX_POINTER_SEGMENTS = C.BYTES.bytes(64);
var MAX_EXPRESSION_BYTES = C.BYTES.kib(2);
var MAX_EXPRESSION_DEPTH = C.BYTES.bytes(8);

function _eachUnquoted(expr, visit) {
  var quote = "";
  for (var i = 0; i < expr.length; i++) {
    var c = expr.charAt(i);
    if (quote) {
      if (c === "\\") { i += 1; continue; }
      if (c === quote) quote = "";
      continue;
    }
    if (c === "'" || c === "\"") { quote = c; continue; }
    if (visit(c, i) === true) return true;
  }
  return false;
}

function _hasFilterExpr(expr) {
  return _eachUnquoted(expr, function (c, i) {
    if (c !== "?") return false;
    var p = _skipSpace(expr, i + 1);
    if (p >= expr.length) return false;
    var n = expr.charAt(p);
    return n === "(" || n === "{" || n === "@" || n === "!" || n === "$";
  });
}

function _hasDeepScan(expr) {
  return _eachUnquoted(expr, function (c, i) {
    return c === "." && expr.charAt(_skipSpace(expr, i + 1)) === ".";
  });
}
function _hasScriptExpr(expr) {
  for (var i = expr.indexOf("("); i !== -1; i = expr.indexOf("(", i + 1)) {
    var p = _skipSpace(expr, i + 1);
    if (expr.charAt(p) !== "@") continue;
    var after = expr.charAt(_skipSpace(expr, p + 1));
    if (after === "." || after === "[") return true;
  }
  return false;
}

function _skipSpace(text, at) {
  var p = at;
  while (p < text.length &&
         codepointClass.inRanges(text.charCodeAt(p), codepointClass.WHITESPACE_RANGES)) p += 1;
  return p;
}
var DYNAMIC_HINTS = Object.freeze([
  "ev" + "al",
  "func" + "tion",
  "n" + "ew ",
  "=>",
  ";",
]);

function _hasControlOrNul(value) {
  for (var i = 0; i < value.length; i++) {
    var c = value.charCodeAt(i);
    if (codepointClass.isForbiddenControlChar(c)) return true;
  }
  if (codepointClass.firstInRanges(value, codepointClass.BIDI_RANGES) !== -1) return true;
  if (codepointClass.firstInRanges(value, codepointClass.ZERO_WIDTH_RANGES) !== -1) return true;
  return false;
}

/**
 * @primitive b.safeJsonPath.validateKey
 * @signature b.safeJsonPath.validateKey(key, opts?)
 * @since     0.8.44
 * @status    stable
 * @related   b.safeJsonPath.validatePointer, b.guardJsonpath.validate
 *
 * Check one JSON object key and return it unchanged.
 *
 * A non-string raises `safe-jsonpath/bad-key`, as does an empty one. Over the
 * byte limit raises `safe-jsonpath/key-too-long`, and a key carrying NUL,
 * control, bidirectional or zero-width characters raises
 * `safe-jsonpath/key-control-char`, because such a key displays as one thing
 * in a log or a UI and matches another in the store.
 *
 * The key is returned rather than rewritten: a key is an identifier, and
 * silently changing one would address a different field than the caller asked
 * for.
 *
 * @opts
 *   maxBytes: number,   // default: the module's MAX_KEY_BYTES
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.safeJsonPath.validateKey("patientId");     // → "patientId"
 */
function validateKey(key, opts) {
  opts = opts || {};
  if (typeof key !== "string") {
    throw _err("safe-jsonpath/bad-key",
      "validateKey: key must be a string; got " + (typeof key));
  }
  if (key.length === 0) {
    throw _err("safe-jsonpath/bad-key",
      "validateKey: key must be non-empty");
  }
  var maxBytes = opts.maxBytes || MAX_KEY_BYTES;
  if (safeBuffer.byteLengthOf(key) > maxBytes) {
    throw _err("safe-jsonpath/key-too-long",
      "validateKey: key exceeds " + maxBytes + " bytes (got " + safeBuffer.byteLengthOf(key) + ")");
  }
  if (_hasControlOrNul(key)) {
    throw _err("safe-jsonpath/key-control-char",
      "validateKey: key contains NUL / control / bidi / zero-width characters");
  }
  return key;
}

/**
 * @primitive b.safeJsonPath.validatePointer
 * @signature b.safeJsonPath.validatePointer(pointer, opts?)
 * @since     0.8.44
 * @status    stable
 * @related   b.safeJsonPath.validateKey, b.safeJsonPath.validateExpression
 *
 * Check a pointer given as an array of segments and return it unchanged. A
 * string segment is a key and goes through `validateKey`; a numeric segment is
 * an array index and has to be a non-negative integer.
 *
 * A pointer that is not an array raises `safe-jsonpath/bad-pointer`, and one
 * longer than the segment limit raises `safe-jsonpath/pointer-too-long`, since
 * depth is what turns a lookup into work proportional to the document. A
 * negative or fractional index raises `safe-jsonpath/pointer-bad-index`, and
 * anything that is neither a string nor a number raises
 * `safe-jsonpath/pointer-bad-segment`.
 *
 * A string segment carries the key checks with it:
 * `safe-jsonpath/bad-key` for an empty one, `safe-jsonpath/key-too-long` over
 * the byte limit, and `safe-jsonpath/key-control-char` for NUL, control,
 * bidirectional or zero-width characters.
 *
 * Taking the pointer as an array rather than a string is the point: there is
 * no separator to escape, so a key containing a dot or a slash cannot become
 * two segments.
 *
 * @opts
 *   maxSegments: number,   // default: the module's MAX_POINTER_SEGMENTS
 *   maxBytes:    number,   // per-key byte limit
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.safeJsonPath.validatePointer(["patients", 0, "name"]);
 */
function validatePointer(pointer, opts) {
  opts = opts || {};
  if (!Array.isArray(pointer)) {
    throw _err("safe-jsonpath/bad-pointer",
      "validatePointer: pointer must be an array of segments; got " + (typeof pointer));
  }
  var maxSeg = opts.maxSegments || MAX_POINTER_SEGMENTS;
  if (pointer.length > maxSeg) {
    throw _err("safe-jsonpath/pointer-too-long",
      "validatePointer: pointer has " + pointer.length + " segments, max " + maxSeg);
  }
  for (var i = 0; i < pointer.length; i++) {
    var seg = pointer[i];
    if (typeof seg === "number") {
      if (!Number.isFinite(seg) || !Number.isInteger(seg) || seg < 0) {
        throw _err("safe-jsonpath/pointer-bad-index",
          "validatePointer: pointer[" + i + "] numeric index must be a non-negative integer");
      }
    } else if (typeof seg === "string") {
      validateKey(seg, opts);
    } else {
      throw _err("safe-jsonpath/pointer-bad-segment",
        "validatePointer: pointer[" + i + "] must be a string key or non-negative integer");
    }
  }
  return pointer;
}

/**
 * @primitive b.safeJsonPath.validateExpression
 * @signature b.safeJsonPath.validateExpression(expr, opts?)
 * @since     0.8.44
 * @status    stable
 * @related   b.safeJsonPath.validatePointer, b.guardJsonpath.validate
 *
 * Check a JSONPath expression string and return it unchanged.
 *
 * A filter expression, `?(...)`, is refused with
 * `safe-jsonpath/filter-expr-refused` whatever it contains. A filter is
 * predicate logic, and a validator cannot tell a safe one built from operator
 * input from an unsafe one, so the answer is to build the path at the call
 * site with bound values.
 *
 * Three more constructs are refused outright for the same reason. A deep scan,
 * `$..`, raises `safe-jsonpath/deep-scan-refused`: it multiplies traversal
 * cost and ignores whatever shape the caller assumed. A script-shaped
 * `(@.x…)` raises `safe-jsonpath/script-expr-refused`, because evaluators that
 * route paths through dynamic code turn that into remote code execution. A
 * JavaScript-source hint anywhere in the expression raises
 * `safe-jsonpath/dynamic-hint-refused`.
 *
 * The remaining refusals are `safe-jsonpath/bad-expression` for a non-string
 * or empty expression, `safe-jsonpath/expression-too-long` over the byte
 * limit, `safe-jsonpath/expression-control-char` for NUL, control,
 * bidirectional or zero-width characters, and
 * `safe-jsonpath/expression-too-deep` when bracket nesting passes `maxDepth`.
 *
 * @opts
 *   maxBytes: number,   // default: the module's MAX_EXPRESSION_BYTES
 *   maxDepth: number,   // bracket-nesting ceiling; default 8
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.safeJsonPath.validateExpression("$.patients[0].name");
 *   try { b.safeJsonPath.validateExpression("$.p[?(@.x=='y')]"); }
 *   catch (e) { e.code; }        // → "safe-jsonpath/filter-expr-refused"
 */
function validateExpression(expr, opts) {
  opts = opts || {};
  if (typeof expr !== "string") {
    throw _err("safe-jsonpath/bad-expression",
      "validateExpression: expr must be a string; got " + (typeof expr));
  }
  if (expr.length === 0) {
    throw _err("safe-jsonpath/bad-expression",
      "validateExpression: expr must be non-empty");
  }
  var maxBytes = opts.maxBytes || MAX_EXPRESSION_BYTES;
  if (safeBuffer.byteLengthOf(expr) > maxBytes) {
    throw _err("safe-jsonpath/expression-too-long",
      "validateExpression: expr exceeds " + maxBytes + " bytes (got " + safeBuffer.byteLengthOf(expr) + ")");
  }
  if (_hasControlOrNul(expr)) {
    throw _err("safe-jsonpath/expression-control-char",
      "validateExpression: expr contains NUL / control / bidi / zero-width characters");
  }
  if (_hasFilterExpr(expr)) {
    throw _err("safe-jsonpath/filter-expr-refused",
      "validateExpression: filter expression '?(...)' refused — operator-supplied filter " +
      "values smuggle predicate logic. Build the path with bound parameters at the " +
      "call site; do not pass operator input through this validator.");
  }
  if (_hasDeepScan(expr)) {
    throw _err("safe-jsonpath/deep-scan-refused",
      "validateExpression: deep-scan '$..' refused on untrusted input — amplifies " +
      "traversal cost and bypasses schema-shape assumptions.");
  }
  if (_hasScriptExpr(expr)) {
    throw _err("safe-jsonpath/script-expr-refused",
      "validateExpression: script-shape '(@.x...)' refused — RCE class in evaluators " +
      "that route paths through dynamic-code execution.");
  }
  for (var i = 0; i < DYNAMIC_HINTS.length; i++) {
    if (expr.indexOf(DYNAMIC_HINTS[i]) !== -1) {
      throw _err("safe-jsonpath/dynamic-hint-refused",
        "validateExpression: expression contains a JS-source hint refused at every profile");
    }
  }
  var depth = 0;
  var maxDepth = opts.maxDepth || MAX_EXPRESSION_DEPTH;
  for (var j = 0; j < expr.length; j++) {
    var ch = expr.charCodeAt(j);
    if (ch === 91  || ch === 40  || ch === 123 ) {
      depth += 1;
      if (depth > maxDepth) {
        throw _err("safe-jsonpath/expression-too-deep",
          "validateExpression: expression bracket nesting exceeds " + maxDepth);
      }
    } else if (ch === 93  || ch === 41  || ch === 125 ) {
      depth -= 1;
    }
  }
  return expr;
}

/**
 * @primitive b.safeJsonPath.validateContainment
 * @signature b.safeJsonPath.validateContainment(value, opts?)
 * @since     0.8.44
 * @status    stable
 * @related   b.safeJsonPath.validateKey, b.safeJson.parseTyped
 *
 * Check a containment shape, the object a JSON column is queried by, and
 * return it unchanged.
 *
 * It walks the whole shape and bounds both dimensions: more than `maxNodes`
 * raises `safe-jsonpath/containment-too-large` and nesting past `maxDepth`
 * raises `safe-jsonpath/containment-too-deep`. A shape is operator input, and
 * a wide or deep one costs the store the walk whether or not it matches
 * anything.
 *
 * Every key goes through the same check as a standalone key, so
 * `safe-jsonpath/bad-key`, `safe-jsonpath/key-too-long` and
 * `safe-jsonpath/key-control-char` reach the caller from here too. A string
 * leaf carrying control, bidirectional or zero-width characters raises
 * `safe-jsonpath/containment-bad-string`, and one longer than the key limit in
 * characters raises `safe-jsonpath/containment-string-too-long`, so a shape
 * cannot match on a value that displays as something else. A leaf that is not a JSON type at
 * all, a function or a symbol, raises
 * `safe-jsonpath/containment-bad-type`.
 *
 * @opts
 *   maxDepth: number,   // nesting ceiling
 *   maxNodes: number,   // total nodes walked; default 1024
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.safeJsonPath.validateContainment({ status: "active", tags: ["a", "b"] });
 */
function validateContainment(value, opts) {
  opts = opts || {};
  var depth = 0;
  var maxDepth = opts.maxDepth || MAX_EXPRESSION_DEPTH;
  var maxNodes = opts.maxNodes || C.BYTES.bytes(1024);
  var nodes = 0;
  function _walk(v) {
    nodes += 1;
    if (nodes > maxNodes) {
      throw _err("safe-jsonpath/containment-too-large",
        "validateContainment: shape exceeds " + maxNodes + " nodes");
    }
    if (depth > maxDepth) {
      throw _err("safe-jsonpath/containment-too-deep",
        "validateContainment: shape nesting exceeds " + maxDepth);
    }
    if (v === null || typeof v === "boolean" || typeof v === "number") return;
    if (typeof v === "string") {
      if (_hasControlOrNul(v)) {
        throw _err("safe-jsonpath/containment-bad-string",
          "validateContainment: string leaf contains NUL / control / bidi / zero-width");
      }
      if (v.length > MAX_KEY_BYTES) {
        throw _err("safe-jsonpath/containment-string-too-long",
          "validateContainment: string leaf exceeds " + MAX_KEY_BYTES + " bytes");
      }
      return;
    }
    if (Array.isArray(v)) {
      depth += 1;
      for (var i = 0; i < v.length; i++) _walk(v[i]);
      depth -= 1;
      return;
    }
    if (typeof v === "object") {
      var noForm = typeof v.toJSON === "function" ? null : canonicalJson._noJsonFormName(v);
      if (noForm !== null) {
        throw _err("safe-jsonpath/containment-bad-type",
          "validateContainment: " + noForm + " has no JSON form; it serializes to {}, " +
          "and a containment match against {} is satisfied by every JSON object");
      }
      depth += 1;
      var keys = Object.keys(v);
      for (var k = 0; k < keys.length; k++) {
        validateKey(keys[k], opts);
        _walk(v[keys[k]]);
      }
      depth -= 1;
      return;
    }
    throw _err("safe-jsonpath/containment-bad-type",
      "validateContainment: unsupported JSON value type '" + (typeof v) + "'");
  }
  _walk(value);
  return value;
}

module.exports = {
  validateKey:         validateKey,
  validatePointer:     validatePointer,
  validateExpression:  validateExpression,
  validateContainment: validateContainment,
  SafeJsonPathError:   SafeJsonPathError,
  MAX_KEY_BYTES:        MAX_KEY_BYTES,
  MAX_POINTER_SEGMENTS: MAX_POINTER_SEGMENTS,
  MAX_EXPRESSION_BYTES: MAX_EXPRESSION_BYTES,
};
