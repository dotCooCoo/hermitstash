// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.jsonPath
 * @nav    Data
 * @title  JSONPath
 *
 * @intro
 *   Query a JSON value with JSONPath (RFC 9535) — the standardized path
 *   language for selecting nodes from a document
 *   (<code>$.store.book[?@.price &lt; 10].title</code>). This is the
 *   query evaluator that complements the framework's JSONPath
 *   <em>guards</em> (<code>b.guardJsonPath</code>, which screen
 *   operator-supplied path strings): <code>query</code> compiles a path
 *   and returns the matched values, <code>paths</code> returns their
 *   normalized locations.
 *
 *   The full RFC 9535 surface is implemented — name / wildcard / index /
 *   slice selectors, descendant segments (<code>..</code>), filter
 *   selectors (<code>?</code>) with comparison and logical operators and
 *   relative (<code>@</code>) / absolute (<code>$</code>) queries, and
 *   the five standard functions <code>length</code>, <code>count</code>,
 *   <code>match</code>, <code>search</code>, and <code>value</code> — with
 *   the spec's well-typedness rules enforced at compile time (a
 *   malformed or ill-typed query is rejected, not silently mis-evaluated).
 *
 * @card
 *   JSONPath query (RFC 9535) — select nodes from a JSON document with
 *   the standard path language: name / wildcard / index / slice /
 *   descendant selectors, <code>?filter</code> expressions, and the five
 *   standard functions, with compile-time well-typedness checks.
 */

var { defineClass } = require("./framework-error");

var JsonPathError = defineClass("JsonPathError", { alwaysPermanent: true });

var MAX_DESCEND_NODES = 1000000;                             // DoS ceiling on nodes visited by a descendant walk
var MAX_TOTAL_NODES = 1000000;                              // DoS ceiling on the running nodelist across ALL segments (chained wildcard/slice/filter cross-product)

// ---------------------------------------------------------------------------
// Parser — recursive descent over the RFC 9535 ABNF.
// ---------------------------------------------------------------------------

function _isBlank(c) { return c === " " || c === "\t" || c === "\n" || c === "\r"; }
function _isDigit(c) { return c >= "0" && c <= "9"; }
// member-name-shorthand name-first: ALPHA / "_" / non-ASCII.
function _isNameFirst(c) { var cc = c.charCodeAt(0); return (c >= "A" && c <= "Z") || (c >= "a" && c <= "z") || c === "_" || cc >= 0x80; }
function _isNameChar(c) { return _isNameFirst(c) || _isDigit(c); }

function _Parser(s) { this.s = s; this.i = 0; this._depth = 0; }

// Nesting-depth cap for the filter-expression recursion (parens + `!`). Without
// it, a deeply-nested filter like `?(((((...)))))` recurses until V8 throws a
// raw RangeError ("Maximum call stack size exceeded") that escapes JsonPathError
// handling — a DoS / unhandled-crash lever on attacker-supplied JSONPath.
var MAX_FILTER_DEPTH = 200;
_Parser.prototype._descend = function () {
  if (++this._depth > MAX_FILTER_DEPTH) {
    throw new JsonPathError("json-path/filter-too-deep",
      "jsonPath: filter expression nesting exceeds " + MAX_FILTER_DEPTH);
  }
};
_Parser.prototype._ascend = function () { this._depth -= 1; };
_Parser.prototype.err = function (msg) { throw new JsonPathError("json-path/invalid", "jsonPath: " + msg + " at index " + this.i); };
_Parser.prototype.peek = function () { return this.i < this.s.length ? this.s.charAt(this.i) : ""; };
_Parser.prototype.eat = function (c) { if (this.peek() !== c) this.err("expected '" + c + "'"); this.i += 1; };
_Parser.prototype.skipBlank = function () { while (_isBlank(this.peek())) this.i += 1; };

_Parser.prototype.parseQuery = function () {
  if (this.peek() !== "$") this.err("query must start with '$'");
  this.i += 1;
  var segments = this.parseSegments();
  if (this.i !== this.s.length) this.err("trailing characters");
  return { type: "root", segments: segments };
};

_Parser.prototype.parseSegments = function () {
  var segs = [];
  for (;;) {
    var save = this.i;
    this.skipBlank();
    var c = this.peek();
    if (c === "[") { segs.push({ kind: "child", selectors: this.parseBracket() }); }
    else if (c === ".") {
      if (this.s.charAt(this.i + 1) === ".") { this.i += 2; segs.push(this.parseDescendant()); }
      else { this.i += 1; segs.push({ kind: "child", selectors: [this.parseShorthand()] }); }
    } else { this.i = save; break; }
  }
  return segs;
};

_Parser.prototype.parseDescendant = function () {
  var c = this.peek();
  if (c === "[") return { kind: "descendant", selectors: this.parseBracket() };
  if (c === "*") { this.i += 1; return { kind: "descendant", selectors: [{ type: "wildcard" }] }; }
  return { kind: "descendant", selectors: [this.parseShorthand()] };
};

_Parser.prototype.parseShorthand = function () {
  var c = this.peek();
  if (c === "*") { this.i += 1; return { type: "wildcard" }; }
  if (!_isNameFirst(c)) this.err("invalid member name");
  var start = this.i; this.i += 1;
  while (_isNameChar(this.peek())) this.i += 1;
  return { type: "name", name: this.s.slice(start, this.i) };
};

_Parser.prototype.parseBracket = function () {
  this.eat("[");
  var selectors = [];
  for (;;) {
    this.skipBlank();
    selectors.push(this.parseSelector());
    this.skipBlank();
    var c = this.peek();
    if (c === ",") { this.i += 1; continue; }
    if (c === "]") { this.i += 1; break; }
    this.err("expected ',' or ']' in selection");
  }
  return selectors;
};

_Parser.prototype.parseSelector = function () {
  var c = this.peek();
  if (c === "*") { this.i += 1; return { type: "wildcard" }; }
  if (c === "'" || c === "\"") return { type: "name", name: this.parseStringLiteral() };
  if (c === "?") { this.i += 1; this.skipBlank(); return { type: "filter", expr: this.parseLogicalOr() }; }
  // index or slice
  if (c === ":" || c === "-" || _isDigit(c)) return this.parseIndexOrSlice();
  this.err("invalid selector");
};

_Parser.prototype.parseIntToken = function () {
  var start = this.i;
  if (this.peek() === "-") this.i += 1;
  if (!_isDigit(this.peek())) this.err("expected integer");
  if (this.peek() === "0") {
    this.i += 1;
    if (_isDigit(this.peek())) this.err("leading zero in integer");
  } else {
    while (_isDigit(this.peek())) this.i += 1;
  }
  var txt = this.s.slice(start, this.i);
  if (txt === "-0") this.err("negative zero");
  var n = Number(txt);
  if (!Number.isSafeInteger(n)) this.err("integer out of range");
  return n;
};

_Parser.prototype.parseIndexOrSlice = function () {
  // Detect slice by looking for ':' before ',' or ']' (whitespace-aware).
  var isSlice = false, j = this.i;
  while (j < this.s.length) {
    var ch = this.s.charAt(j);
    if (ch === ":") { isSlice = true; break; }
    if (ch === "," || ch === "]") break;
    if (_isBlank(ch)) { j += 1; continue; }
    if (ch === "-" || _isDigit(ch)) { j += 1; continue; }
    break;
  }
  if (!isSlice) { return { type: "index", index: this.parseIntToken() }; }
  // slice: [start] ":" [end] [ ":" [step] ]
  var start = null, end = null, step = null;
  this.skipBlank();
  if (this.peek() === "-" || _isDigit(this.peek())) start = this.parseIntToken();
  this.skipBlank(); this.eat(":"); this.skipBlank();
  if (this.peek() === "-" || _isDigit(this.peek())) end = this.parseIntToken();
  this.skipBlank();
  if (this.peek() === ":") {
    this.i += 1; this.skipBlank();
    if (this.peek() === "-" || _isDigit(this.peek())) step = this.parseIntToken();
  }
  return { type: "slice", start: start, end: end, step: step };
};

_Parser.prototype.parseStringLiteral = function () {
  var quote = this.peek(); this.i += 1;
  var out = "";
  for (;;) {
    if (this.i >= this.s.length) this.err("unterminated string");
    var c = this.s.charAt(this.i); this.i += 1;
    if (c === quote) return out;
    if (c === "\\") {
      var e = this.s.charAt(this.i); this.i += 1;
      if (e === "n") out += "\n";
      else if (e === "t") out += "\t";
      else if (e === "r") out += "\r";
      else if (e === "b") out += "\b";
      else if (e === "f") out += "\f";
      else if (e === "/") out += "/";
      else if (e === "\\") out += "\\";
      else if (e === quote) out += quote;
      else if (e === "u") {
        var hex = this.s.substr(this.i, 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.err("invalid \\u escape");
        var cp = parseInt(hex, 16); this.i += 4;             // base-16 radix for \uXXXX
        // Surrogate pair handling.
        if (cp >= 0xD800 && cp <= 0xDBFF && this.s.substr(this.i, 2) === "\\u") {
          var hex2 = this.s.substr(this.i + 2, 4);
          if (/^[0-9a-fA-F]{4}$/.test(hex2)) {
            var lo = parseInt(hex2, 16);                     // base-16 radix for \uXXXX low surrogate
            if (lo >= 0xDC00 && lo <= 0xDFFF) { out += String.fromCharCode(cp, lo); this.i += 6; continue; }
          }
          this.err("invalid surrogate pair");
        }
        if (cp >= 0xD800 && cp <= 0xDFFF) this.err("lone surrogate in string");
        out += String.fromCharCode(cp);
      } else this.err("invalid escape");
    } else {
      var cc = c.charCodeAt(0);
      if (cc <= 0x1f) this.err("unescaped control character in string");
      // RFC 9535: a literal of the SAME quote must be escaped; the other
      // quote is allowed literally (handled by the quote check above).
      out += c;
    }
  }
};

// --- filter expression grammar ---
// Each node carries a `vtype`: "value" (ValueType), "logical" (LogicalType),
// or "nodes" (NodesType) for well-typedness checks.

_Parser.prototype.parseLogicalOr = function () {
  var left = this.parseLogicalAnd();
  for (;;) {
    this.skipBlank();
    if (this.s.substr(this.i, 2) === "||") { this.i += 2; this.skipBlank(); var r = this.parseLogicalAnd(); left = { type: "or", a: left, b: r, vtype: "logical" }; }
    else break;
  }
  return left;
};
_Parser.prototype.parseLogicalAnd = function () {
  var left = this.parseBasic();
  for (;;) {
    this.skipBlank();
    if (this.s.substr(this.i, 2) === "&&") { this.i += 2; this.skipBlank(); var r = this.parseBasic(); left = { type: "and", a: left, b: r, vtype: "logical" }; }
    else break;
  }
  return left;
};
_Parser.prototype.parseBasic = function () {
  this.skipBlank();
  if (this.peek() === "!") { this.i += 1; this.skipBlank(); this._descend(); var inner = this.parseBasic(); this._ascend(); this._requireTestable(inner); return { type: "not", e: inner, vtype: "logical" }; }
  if (this.peek() === "(") {
    this.i += 1; this.skipBlank(); this._descend(); var e = this.parseLogicalOr(); this._ascend(); this.skipBlank(); this.eat(")");
    return e;
  }
  // comparison or test
  var first = this.parseComparableOrQuery();
  this.skipBlank();
  var op = this._peekCompareOp();
  if (op) {
    this.i += op.length; this.skipBlank();
    var second = this.parseComparableOrQuery();
    this._requireComparable(first); this._requireComparable(second);
    return { type: "compare", op: op, a: first, b: second, vtype: "logical" };
  }
  // test-expr: a query (existence) or a LogicalType function
  this._requireTestable(first);
  return first;
};

_Parser.prototype._peekCompareOp = function () {
  var two = this.s.substr(this.i, 2);
  if (two === "==" || two === "!=" || two === "<=" || two === ">=") return two;
  var one = this.peek();
  if (one === "<" || one === ">") return one;
  return null;
};

// A comparable: literal / singular-query / function-expr. A query here may
// be non-singular (NodesType) when used as a test; the caller checks type.
_Parser.prototype.parseComparableOrQuery = function () {
  var c = this.peek();
  if (c === "'" || c === "\"") return { type: "lit", value: this.parseStringLiteral(), vtype: "value" };
  if (c === "$" || c === "@") return this.parseFilterQuery();
  if (_isDigit(c) || c === "-") return { type: "lit", value: this.parseNumber(), vtype: "value" };
  if (this.s.substr(this.i, 4) === "true") { this.i += 4; return { type: "lit", value: true, vtype: "value" }; }
  if (this.s.substr(this.i, 5) === "false") { this.i += 5; return { type: "lit", value: false, vtype: "value" }; }
  if (this.s.substr(this.i, 4) === "null") { this.i += 4; return { type: "lit", value: null, vtype: "value" }; }
  // function call
  if (/^[a-z]/.test(c)) return this.parseFunction();
  this.err("expected a comparable or query in filter");
};

_Parser.prototype.parseNumber = function () {
  var start = this.i;
  if (this.peek() === "-") this.i += 1;
  if (this.peek() === "0") this.i += 1;
  else { if (!_isDigit(this.peek())) this.err("invalid number"); while (_isDigit(this.peek())) this.i += 1; }
  if (this.peek() === ".") { this.i += 1; if (!_isDigit(this.peek())) this.err("invalid fraction"); while (_isDigit(this.peek())) this.i += 1; }
  if (this.peek() === "e" || this.peek() === "E") {
    this.i += 1; if (this.peek() === "+" || this.peek() === "-") this.i += 1;
    if (!_isDigit(this.peek())) this.err("invalid exponent"); while (_isDigit(this.peek())) this.i += 1;
  }
  return Number(this.s.slice(start, this.i));
};

_Parser.prototype.parseFilterQuery = function () {
  var rootChar = this.peek(); this.i += 1; // $ or @
  var segments = this.parseSegments();
  var singular = segments.every(function (seg) {
    return seg.kind === "child" && seg.selectors.length === 1 &&
      (seg.selectors[0].type === "name" || seg.selectors[0].type === "index");
  });
  return { type: "query", root: rootChar, segments: segments, singular: singular, vtype: singular ? "value" : "nodes" };
};

var FUNCTIONS = {
  length: { params: ["value"], ret: "value" },
  count: { params: ["nodes"], ret: "value" },
  value: { params: ["nodes"], ret: "value" },
  match: { params: ["value", "value"], ret: "logical" },
  search: { params: ["value", "value"], ret: "logical" },
};

_Parser.prototype.parseFunction = function () {
  var start = this.i;
  while (/[a-z]/.test(this.peek()) || this.peek() === "_" || _isDigit(this.peek())) this.i += 1;
  var name = this.s.slice(start, this.i);
  if (!Object.prototype.hasOwnProperty.call(FUNCTIONS, name)) this.err("unknown function '" + name + "'");
  var spec = FUNCTIONS[name];
  this.eat("(");
  var args = [];
  this.skipBlank();
  if (this.peek() !== ")") {
    for (;;) {
      this.skipBlank();
      args.push(this.parseFunctionArg());
      this.skipBlank();
      if (this.peek() === ",") { this.i += 1; continue; }
      break;
    }
  }
  this.skipBlank(); this.eat(")");
  if (args.length !== spec.params.length) this.err("function '" + name + "' expects " + spec.params.length + " argument(s)");
  for (var k = 0; k < args.length; k++) {
    if (!_argMatches(spec.params[k], args[k])) this.err("function '" + name + "' argument " + (k + 1) + " type mismatch");
  }
  return { type: "func", name: name, args: args, vtype: spec.ret };
};

_Parser.prototype.parseFunctionArg = function () {
  var c = this.peek();
  if (c === "'" || c === "\"") return { type: "lit", value: this.parseStringLiteral(), vtype: "value" };
  if (c === "$" || c === "@") return this.parseFilterQuery();
  if (_isDigit(c) || c === "-") return { type: "lit", value: this.parseNumber(), vtype: "value" };
  if (this.s.substr(this.i, 4) === "true") { this.i += 4; return { type: "lit", value: true, vtype: "value" }; }
  if (this.s.substr(this.i, 5) === "false") { this.i += 5; return { type: "lit", value: false, vtype: "value" }; }
  if (this.s.substr(this.i, 4) === "null") { this.i += 4; return { type: "lit", value: null, vtype: "value" }; }
  if (/^[a-z]/.test(c)) return this.parseFunction();
  if (c === "!" || c === "(") return this.parseLogicalOr();   // logical arg (none of the std funcs take it, caught by type check)
  this.err("invalid function argument");
};

// A function parameter of declared type accepts: value←value-typed arg
// (literal / singular query / value-returning function); nodes←any query
// or nodes-returning function; logical←logical expr or logical function.
function _argMatches(param, arg) {
  if (param === "value") return arg.vtype === "value" || (arg.type === "query" && arg.singular);
  if (param === "nodes") return arg.type === "query" || (arg.type === "func" && arg.vtype === "nodes");
  if (param === "logical") return arg.vtype === "logical";
  return false;
}

_Parser.prototype._requireComparable = function (node) {
  // Comparables must be ValueType: a literal, a SINGULAR query, or a
  // value-returning function. A non-singular query or logical/nodes
  // function is ill-typed.
  if (node.type === "lit") return;
  if (node.type === "query") { if (!node.singular) this.err("non-singular query is not comparable"); return; }
  if (node.type === "func") { if (node.vtype !== "value") this.err("function '" + node.name + "' is not comparable (not ValueType)"); return; }
  this.err("operand is not comparable");
};
_Parser.prototype._requireTestable = function (node) {
  // A test-expr is a query (existence) or a LogicalType function; a
  // ValueType function (length/count/value) is NOT a valid test.
  if (node.type === "query") return;
  if (node.type === "func") { if (node.vtype !== "logical") this.err("function '" + node.name + "' is not a valid test (not LogicalType)"); return; }
  if (node.vtype === "logical") return;
  this.err("expression is not a valid test");
};

function _parse(path) {
  if (typeof path !== "string") throw new JsonPathError("json-path/bad-arg", "jsonPath: path must be a string");
  return new _Parser(path).parseQuery();
}

// ---------------------------------------------------------------------------
// Evaluator — produces a nodelist of { value, path: [tokens] }.
// ---------------------------------------------------------------------------

function _isObject(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }

function _applySelector(sel, node, root, out) {
  var v = node.value;
  if (sel.type === "name") {
    if (_isObject(v) && Object.prototype.hasOwnProperty.call(v, sel.name)) out.push({ value: v[sel.name], path: node.path.concat(sel.name) });
  } else if (sel.type === "wildcard") {
    if (Array.isArray(v)) { for (var i = 0; i < v.length; i++) out.push({ value: v[i], path: node.path.concat(i) }); }
    else if (_isObject(v)) { Object.keys(v).forEach(function (k) { out.push({ value: v[k], path: node.path.concat(k) }); }); }
  } else if (sel.type === "index") {
    if (Array.isArray(v)) { var idx = sel.index < 0 ? v.length + sel.index : sel.index; if (idx >= 0 && idx < v.length) out.push({ value: v[idx], path: node.path.concat(idx) }); }
  } else if (sel.type === "slice") {
    if (Array.isArray(v)) _applySlice(sel, v, node, out);
  } else if (sel.type === "filter") {
    var items = Array.isArray(v) ? v.map(function (e, i) { return { value: e, path: node.path.concat(i) }; })
      : _isObject(v) ? Object.keys(v).map(function (k) { return { value: v[k], path: node.path.concat(k) }; }) : [];
    items.forEach(function (it) { if (_truthy(_evalLogical(sel.expr, it, root))) out.push(it); });
  }
}

function _applySlice(sel, arr, node, out) {
  var len = arr.length;
  var step = sel.step === null ? 1 : sel.step;
  if (step === 0) return;
  var lower, upper, start, end;
  if (step > 0) {
    start = sel.start === null ? 0 : sel.start;
    end = sel.end === null ? len : sel.end;
    lower = start < 0 ? Math.max(len + start, 0) : Math.min(start, len);
    upper = end < 0 ? Math.max(len + end, 0) : Math.min(end, len);
    for (var i = lower; i < upper; i += step) out.push({ value: arr[i], path: node.path.concat(i) });
  } else {
    start = sel.start === null ? len - 1 : sel.start;
    end = sel.end === null ? -len - 1 : sel.end;
    lower = start < 0 ? Math.max(len + start, -1) : Math.min(start, len - 1);
    upper = end < 0 ? Math.max(len + end, -1) : Math.min(end, len - 1);
    for (var j = lower; j > upper; j += step) out.push({ value: arr[j], path: node.path.concat(j) });
  }
}

function _descend(node, acc, budget) {
  acc.push(node);
  if (budget.n++ > MAX_DESCEND_NODES) throw new JsonPathError("json-path/too-large", "jsonPath: descendant walk exceeded the node cap");
  var v = node.value;
  if (Array.isArray(v)) { for (var i = 0; i < v.length; i++) _descend({ value: v[i], path: node.path.concat(i) }, acc, budget); }
  else if (_isObject(v)) { Object.keys(v).forEach(function (k) { _descend({ value: v[k], path: node.path.concat(k) }, acc, budget); }); }
}

function _evalSegments(segments, root) {
  var nodes = [{ value: root, path: [] }];
  for (var s = 0; s < segments.length; s++) {
    var seg = segments[s];
    var next = [];
    var base = nodes;
    if (seg.kind === "descendant") {
      var acc = []; var budget = { n: 0 };
      nodes.forEach(function (nd) { _descend(nd, acc, budget); });
      base = acc;
    }
    base.forEach(function (nd) { seg.selectors.forEach(function (sel) { _applySelector(sel, nd, root, next); }); });
    // Cap the running nodelist across the WHOLE query, not just per descendant
    // walk: chained wildcard/slice/filter selectors multiply the nodelist each
    // segment ([*][*][*]…), an OOM lever the per-`_descend` budget never sees.
    if (next.length > MAX_TOTAL_NODES) {
      throw new JsonPathError("json-path/too-large",
        "jsonPath: nodelist exceeded " + MAX_TOTAL_NODES + " nodes (chained selector cross-product)");
    }
    nodes = next;
  }
  return nodes;
}

// --- filter evaluation ---
var NOTHING = { __nothing: true };   // the "Nothing" value (missing node)

function _singularValue(q, current, root) {
  var node = q.root === "$" ? root : current.value;
  for (var i = 0; i < q.segments.length; i++) {
    var sel = q.segments[i].selectors[0];
    if (sel.type === "name") {
      if (!_isObject(node) || !Object.prototype.hasOwnProperty.call(node, sel.name)) return NOTHING;
      node = node[sel.name];
    } else { // index
      if (!Array.isArray(node)) return NOTHING;
      var idx = sel.index < 0 ? node.length + sel.index : sel.index;
      if (idx < 0 || idx >= node.length) return NOTHING;
      node = node[idx];
    }
  }
  return node;
}

function _queryNodes(q, current, root) {
  var startVal = q.root === "$" ? root : current.value;
  return _evalSegments(q.segments, startVal);
}

function _evalComparable(node, current, root) {
  if (node.type === "lit") return node.value;
  if (node.type === "query") return _singularValue(node, current, root);
  if (node.type === "func") return _evalFunctionValue(node, current, root);
  return NOTHING;
}

function _deepEqual(a, b) {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== "object" || typeof b !== "object") return a === b;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) { if (a.length !== b.length) return false; for (var i = 0; i < a.length; i++) if (!_deepEqual(a[i], b[i])) return false; return true; }
  var ka = Object.keys(a), kb = Object.keys(b);
  if (ka.length !== kb.length) return false;
  for (var j = 0; j < ka.length; j++) { if (!Object.prototype.hasOwnProperty.call(b, ka[j]) || !_deepEqual(a[ka[j]], b[ka[j]])) return false; }
  return true;
}

function _equals(a, b) {
  var aN = a === NOTHING, bN = b === NOTHING;
  if (aN || bN) return aN && bN;                             // Nothing equals only Nothing
  return _deepEqual(a, b);
}
// Strict ordering "a < b": defined only for two numbers or two strings
// (RFC 9535 §2.3.5.2.2); anything else (incl. Nothing) is not <.
function _less(a, b) {
  if (a === NOTHING || b === NOTHING) return false;
  var comparable = (typeof a === "number" && typeof b === "number") || (typeof a === "string" && typeof b === "string");
  if (!comparable) return false;
  return a < b;
}
function _compare(op, a, b) {
  switch (op) {
    case "==": return _equals(a, b);
    case "!=": return !_equals(a, b);
    case "<":  return _less(a, b);
    case ">":  return _less(b, a);
    case "<=": return _less(a, b) || _equals(a, b);          // §2.3.5.2.2: <= is < OR ==
    case ">=": return _less(b, a) || _equals(a, b);
    default:   return false;
  }
}

function _truthy(x) { return x === true; }

function _evalLogical(node, current, root) {
  switch (node.type) {
    case "or": return _evalLogical(node.a, current, root) || _evalLogical(node.b, current, root);
    case "and": return _evalLogical(node.a, current, root) && _evalLogical(node.b, current, root);
    case "not": return !_evalLogical(node.e, current, root);
    case "compare": return _compare(node.op, _evalComparable(node.a, current, root), _evalComparable(node.b, current, root));
    case "query": return _queryNodes(node, current, root).length > 0;       // existence test
    case "func": return _evalFunctionLogical(node, current, root);
    default: return false;
  }
}

// --- standard functions ---
function _funcArgValue(arg, current, root) {
  if (arg.type === "lit") return arg.value;
  if (arg.type === "query") return _singularValue(arg, current, root);   // ValueType from singular query
  if (arg.type === "func") return _evalFunctionValue(arg, current, root);
  return NOTHING;
}
function _funcArgNodes(arg, current, root) {
  if (arg.type === "query") return _queryNodes(arg, current, root);
  if (arg.type === "func") { var v = _evalFunctionValue(arg, current, root); return v === NOTHING ? [] : [{ value: v, path: [] }]; }
  return [];
}

function _evalFunctionValue(node, current, root) {
  if (node.name === "length") {
    var v = _funcArgValue(node.args[0], current, root);
    if (v === NOTHING) return NOTHING;                       // length(Nothing) = Nothing (the sentinel is itself an object)
    if (typeof v === "string") return Array.from(v).length;
    if (Array.isArray(v)) return v.length;
    if (_isObject(v)) return Object.keys(v).length;
    return NOTHING;
  }
  if (node.name === "count") return _funcArgNodes(node.args[0], current, root).length;
  if (node.name === "value") { var ns = _funcArgNodes(node.args[0], current, root); return ns.length === 1 ? ns[0].value : NOTHING; }
  return NOTHING;
}

function _iRegexpToJs(pattern, anchored) {
  // I-Regexp (RFC 9485) is close to a JS regex subset. Translate the one
  // systematic difference — "." must not match line separators — and
  // (for match) anchor the whole input.
  var translated = pattern.replace(/(\\.)|(\[(?:\\.|[^\]\\])*\])|\./g, function (m, esc, cls) {
    if (esc) return esc;
    if (cls) return cls;
    return "[^\\n\\r]";
  });
  // The pattern is the I-Regexp argument of an RFC 9535 match()/search()
  // filter — translated (not raw) and used only as a boolean test.
  return new RegExp(anchored ? "^(?:" + translated + ")$" : translated, "su");   // allow:dynamic-regex — translated I-Regexp from a match()/search() filter argument
}
function _evalFunctionLogical(node, current, root) {
  var input = _funcArgValue(node.args[0], current, root);
  var pat = _funcArgValue(node.args[1], current, root);
  if (typeof input !== "string" || typeof pat !== "string") return false;
  var re;
  try { re = _iRegexpToJs(pat, node.name === "match"); } catch (_e) { return false; }
  return re.test(input);
}

/**
 * @primitive b.jsonPath.query
 * @signature b.jsonPath.query(doc, path)
 * @since     0.12.61
 * @status    stable
 * @compliance soc2
 * @related   b.jsonPath.paths, b.guardJsonPath.gate
 *
 * Evaluate an RFC 9535 JSONPath query against a JSON value and return the
 * array of matched node values (the nodelist, in document order). The
 * full path language is supported — name / wildcard / index / slice
 * selectors, descendant segments (<code>..</code>), and filter
 * selectors (<code>?</code>) with comparisons, <code>&&</code> /
 * <code>||</code> / <code>!</code>, relative (<code>@</code>) and
 * absolute (<code>$</code>) queries, and the functions
 * <code>length</code> / <code>count</code> / <code>match</code> /
 * <code>search</code> / <code>value</code>. A malformed or ill-typed
 * query throws <code>json-path/invalid</code>.
 *
 * @example
 *   b.jsonPath.query({ a: [{ p: 1 }, { p: 9 }] }, "$.a[?@.p > 5].p");
 *   // → [9]
 */
function query(doc, path) {
  var ast = _parse(path);
  return _evalSegments(ast.segments, doc).map(function (n) { return n.value; });
}

// RFC 9535 §2.7: a normalized-path name is single-quoted and MUST escape
// `'`, `\`, and every control code (%x0-1F) — the latter as the named
// short escape (\b \t \n \f \r) or \uXXXX. Emitting a raw control char
// produces a path that no longer round-trips through the parser (which
// rejects unescaped control characters in a string literal).
function _normalizeName(name) {
  var out = "";
  for (var i = 0; i < name.length; i++) {
    var ch = name.charAt(i), cc = name.charCodeAt(i);
    if (ch === "'") out += "\\'";
    else if (ch === "\\") out += "\\\\";
    else if (cc === 0x08) out += "\\b";
    else if (cc === 0x09) out += "\\t";
    else if (cc === 0x0a) out += "\\n";
    else if (cc === 0x0c) out += "\\f";
    else if (cc === 0x0d) out += "\\r";
    else if (cc < 0x20) out += "\\u" + ("0000" + cc.toString(16)).slice(-4);
    else out += ch;
  }
  return out;
}

function _normalizedPath(tokens) {
  var out = "$";
  for (var i = 0; i < tokens.length; i++) {
    var t = tokens[i];
    if (typeof t === "number") out += "[" + t + "]";
    else out += "['" + _normalizeName(String(t)) + "']";
  }
  return out;
}

/**
 * @primitive b.jsonPath.paths
 * @signature b.jsonPath.paths(doc, path)
 * @since     0.12.61
 * @status    stable
 * @related   b.jsonPath.query
 *
 * Like <code>query</code>, but returns the normalized-path location of
 * each match (RFC 9535 §2.7 normalized paths, e.g.
 * <code>$['a'][1]['p']</code>) instead of the values — useful for
 * reporting or for building a follow-up patch.
 *
 * @example
 *   b.jsonPath.paths({ a: [{ p: 1 }, { p: 9 }] }, "$.a[?@.p > 5].p");
 *   // → ["$['a'][1]['p']"]
 */
function paths(doc, path) {
  var ast = _parse(path);
  return _evalSegments(ast.segments, doc).map(function (n) { return _normalizedPath(n.path); });
}

module.exports = {
  query:         query,
  paths:         paths,
  JsonPathError: JsonPathError,
};
