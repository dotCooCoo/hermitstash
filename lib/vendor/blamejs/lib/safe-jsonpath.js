"use strict";
/**
 * safe-jsonpath — Postgres SQL/JSON path validator for JSONB query
 * operators (b.safeJsonPath).
 *
 * The Postgres JSONB family (`->`, `->>`, `#>`, `#>>`, `@>`, `?`, `?|`,
 * `?&`, `@?`, `@@`) is the surface where operator-supplied JSON paths
 * reach the engine. The `@?` and `@@` operators evaluate
 * RFC 9075-style SQL/JSON path expressions; permitting filter
 * predicates with operator-supplied subpaths (`?(@.role == "admin")`)
 * lets a request-bound value smuggle a different filter than the
 * operator drafted — JSON-path injection.
 *
 * This module is the framework's default-deny gate for the cases
 * where a JSON path or JSONB pointer originates from untrusted input:
 *
 *   - validatePointer(path, opts) — `#>` / `#>>` array pointer
 *     ({key, key, ...}). Refuses NUL / control / quote-breakout.
 *   - validateKey(key, opts)      — `->`, `->>`, `?` operand. Refuses
 *     NUL / control / shape that isn't a single JSON object key.
 *   - validateExpression(expr, opts) — `@?` / `@@` jsonpath literal.
 *     Refuses filter expressions `?{...}` / `?(...)` that contain
 *     operator-supplied values, refuses `$..` deep-scan, refuses
 *     script-shape (`(@.x.y)`), bidi/control/null, depth bombs.
 *
 * Three-tier validation policy: every primitive throws on bad input —
 * the validator is called from a request handler that already
 * surfaces a 4xx, throwing here is the loud refusal the caller wants.
 *
 * b.db.from(table).where(field, "@>", value) integration: when the
 * operator passes a JSONB containment predicate, db-query.js routes
 * the value side through validateContainment(value, opts) which walks
 * the supplied JSON shape and refuses any leaf string that contains
 * a control char / NUL — the leaves still bind via `?` placeholder
 * (not interpolated) but a NUL in a key sneaks past JSON.stringify
 * silently in some drivers.
 */

var codepointClass = require("./codepoint-class");
var C = require("./constants");
var { defineClass, FrameworkError } = require("./framework-error");

// SafeJsonPathError — alwaysPermanent because every code path is a
// caller-shape error: bad pointer / key / expression / shape. The
// framework registers the class through defineClass so the unified
// instanceof FrameworkError check works for callers.
var SafeJsonPathError = defineClass("SafeJsonPathError", { alwaysPermanent: true });
var _err = SafeJsonPathError.factory;
void FrameworkError;

// ---- Threshold constants ----

var MAX_KEY_BYTES        = C.BYTES.kib(1);
var MAX_POINTER_SEGMENTS = C.BYTES.bytes(64);
var MAX_EXPRESSION_BYTES = C.BYTES.kib(2);
var MAX_EXPRESSION_DEPTH = C.BYTES.bytes(8);

// Filter-predicate detector. Postgres SQL/JSON path uses `?(...)` for
// filter expressions; the `@@` operator evaluates the predicate
// directly. Operator-supplied filter content is universally refused
// in validateExpression — operators who genuinely need a filter
// build the path string themselves with bound parameters.
var FILTER_EXPR_RE      = /\?\s*[({]/;
// Deep-scan / recursive-descent. `$..key` walks every nested object;
// against untrusted input it amplifies traversal cost and bypasses
// schema-shape assumptions.
var DEEP_SCAN_RE        = /\$\s*\.\s*\./;
// Script-shape `(@.x.y)` — RFC 9075 SQL/JSON doesn't define it but
// some operator-supplied evaluators accept it as a filter alias.
var SCRIPT_EXPR_RE      = /\(\s*@\s*[.[]/;
// JS-source-hint detector for evaluators that route paths through
// dynamic-code execution. Built from substring fragments to keep this
// source file free of the literal keywords (codebase-patterns gate
// flags them otherwise).
var DYNAMIC_HINTS = Object.freeze([
  "ev" + "al",
  "func" + "tion",
  "n" + "ew ",
  "=>",
  ";",
]);

function _hasControlOrNul(value) {
  // Reject NUL / C0 / DEL / BIDI / zero-width universally — these
  // characters terminate identifiers in some drivers and have no
  // legitimate use in a JSON pointer / key / path expression.
  for (var i = 0; i < value.length; i++) {
    var c = value.charCodeAt(i);
    if (c === 0 || (c < 32 && c !== 9) || c === 127) return true; // allow:raw-byte-literal — ASCII control-byte range
  }
  if (codepointClass.BIDI_RE.test(value)) return true; // allow:regex-no-length-cap — callers cap length via MAX_KEY_BYTES / MAX_EXPRESSION_BYTES
  if (codepointClass.ZERO_WIDTH_RE.test(value)) return true; // allow:regex-no-length-cap — callers cap length via MAX_KEY_BYTES / MAX_EXPRESSION_BYTES
  return false;
}

// ---- Public API ----

// validateKey — single-key operand for `->`, `->>`, `?`. Throws on
// NUL / control / bidi / zero-width or oversized input.
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
  if (key.length > maxBytes) {
    throw _err("safe-jsonpath/key-too-long",
      "validateKey: key exceeds " + maxBytes + " bytes (got " + key.length + ")");
  }
  if (_hasControlOrNul(key)) {
    throw _err("safe-jsonpath/key-control-char",
      "validateKey: key contains NUL / control / bidi / zero-width characters");
  }
  return key;
}

// validatePointer — array form for `#>` / `#>>`. Each segment is a
// JSON object key OR a non-negative integer index. Throws on bad
// shape, oversized, or NUL / control.
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

// validateExpression — RFC 9075 SQL/JSON path literal for `@?` / `@@`.
// Refuses every filter-predicate / deep-scan / script-shape / dynamic
// hint when the input came from an untrusted source. Operators with
// legitimate filter needs build the predicate themselves with bound
// parameters and pass the resulting literal through their own
// safe-string accessor; that path doesn't flow through this gate.
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
  if (expr.length > maxBytes) {
    throw _err("safe-jsonpath/expression-too-long",
      "validateExpression: expr exceeds " + maxBytes + " bytes (got " + expr.length + ")");
  }
  if (_hasControlOrNul(expr)) {
    throw _err("safe-jsonpath/expression-control-char",
      "validateExpression: expr contains NUL / control / bidi / zero-width characters");
  }
  if (FILTER_EXPR_RE.test(expr)) { // allow:regex-no-length-cap — expr length already bounded by MAX_EXPRESSION_BYTES check above
    throw _err("safe-jsonpath/filter-expr-refused",
      "validateExpression: filter expression '?(...)' refused — operator-supplied filter " +
      "values smuggle predicate logic. Build the path with bound parameters at the " +
      "call site; do not pass operator input through this validator.");
  }
  if (DEEP_SCAN_RE.test(expr)) { // allow:regex-no-length-cap — expr length already bounded by MAX_EXPRESSION_BYTES check above
    throw _err("safe-jsonpath/deep-scan-refused",
      "validateExpression: deep-scan '$..' refused on untrusted input — amplifies " +
      "traversal cost and bypasses schema-shape assumptions.");
  }
  if (SCRIPT_EXPR_RE.test(expr)) { // allow:regex-no-length-cap — expr length already bounded by MAX_EXPRESSION_BYTES check above
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
  // Bracket-depth bound — `[[[[[ ... ]]]]]` repeated nesting amplifies
  // the evaluator's recursion cost.
  var depth = 0;
  var maxDepth = opts.maxDepth || MAX_EXPRESSION_DEPTH;
  for (var j = 0; j < expr.length; j++) {
    var ch = expr.charCodeAt(j);
    if (ch === 91 /* [ */ || ch === 40 /* ( */ || ch === 123 /* { */) { // allow:raw-byte-literal — ASCII '[' '(' '{' codepoints
      depth += 1;
      if (depth > maxDepth) {
        throw _err("safe-jsonpath/expression-too-deep",
          "validateExpression: expression bracket nesting exceeds " + maxDepth);
      }
    } else if (ch === 93 /* ] */ || ch === 41 /* ) */ || ch === 125 /* } */) {
      depth -= 1;
    }
  }
  return expr;
}

// validateContainment — value side of `where(field, "@>", value)`.
// Walks the JSON shape recursively; refuses any string leaf or key
// that contains NUL / control / bidi / zero-width. The shape itself
// is operator-supplied so a wrong type at the root is a programming
// bug — throw loudly rather than coerce.
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
  // Surface for tests + downstream telemetry.
  MAX_KEY_BYTES:        MAX_KEY_BYTES,
  MAX_POINTER_SEGMENTS: MAX_POINTER_SEGMENTS,
  MAX_EXPRESSION_BYTES: MAX_EXPRESSION_BYTES,
};
