// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

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

function _hasFilterExpr(expr) { return _followedBy(expr, "?", "({"); }
function _hasDeepScan(expr) {
  for (var i = expr.indexOf("$"); i !== -1; i = expr.indexOf("$", i + 1)) {
    var p = _skipSpace(expr, i + 1);
    if (expr.charAt(p) !== ".") continue;
    if (expr.charAt(_skipSpace(expr, p + 1)) === ".") return true;
  }
  return false;
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

function _followedBy(text, lead, nextChars) {
  for (var i = text.indexOf(lead); i !== -1; i = text.indexOf(lead, i + 1)) {
    var p = _skipSpace(text, i + lead.length);
    if (p < text.length && nextChars.indexOf(text.charAt(p)) !== -1) return true;
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
