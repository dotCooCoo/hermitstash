// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.jsonPath (RFC 9535 JSONPath query).
 * Oracle: a representative subset of the official
 * jsonpath-compliance-test-suite (cts.json) — selectors, filters,
 * functions, and invalid-selector rejections — plus explicit
 * wildcard / slice / descendant / count / value / paths / DoS checks.
 * (The full 703-case suite was run green during development.)
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var jp = b.jsonPath;
function code(fn){try{fn();return "NO-THROW";}catch(e){return e.code;}}
function eq(a,b){return JSON.stringify(a)===JSON.stringify(b);}

// Curated cts cases (selector + document + result|results, or invalid).
var CTS = [
  {"name":"basic, root","selector":"$","document":["first","second"],"result":[["first","second"]]},
  {"name":"basic, name shorthand","selector":"$.a","document":{"a":"A","b":"B"},"result":["A"]},
  {"name":"index selector, negative","selector":"$[-1]","document":["first","second"],"result":["second"]},
  {"name":"filter, less than or equal to null","selector":"$[?@.a<=null]","document":[{"a":null,"d":"e"},{"a":"c","d":"f"}],"result":[{"a":null,"d":"e"}]},
  {"name":"filter, greater than or equal to true","selector":"$[?@.a>=true]","document":[{"a":true,"d":"e"},{"a":"c","d":"f"}],"result":[{"a":true,"d":"e"}]},
  {"name":"filter, and","selector":"$[?@.a>0&&@.a<10]","document":[{"a":-10,"d":"e"},{"a":5,"d":"f"},{"a":20,"d":"f"}],"result":[{"a":5,"d":"f"}]},
  {"name":"filter, or","selector":"$[?@.a=='b'||@.a=='d']","document":[{"a":"a","d":"e"},{"a":"b","d":"f"},{"a":"c","d":"f"},{"a":"d","d":"f"}],"result":[{"a":"b","d":"f"},{"a":"d","d":"f"}]},
  {"name":"filter, nested","selector":"$[?@[?@>1]]","document":[[0],[0,1],[0,1,2],[42]],"result":[[0,1,2],[42]]},
  {"name":"functions, length, string data","selector":"$[?length(@.a)>=2]","document":[{"a":"ab"},{"a":"d"}],"result":[{"a":"ab"}]},
  {"name":"functions, match, found match","selector":"$[?match(@.a, 'a.*')]","document":[{"a":"ab"}],"result":[{"a":"ab"}]},
  {"name":"functions, search, at the end","selector":"$[?search(@.a, 'a.*')]","document":[{"a":"the end is ab"}],"result":[{"a":"the end is ab"}]},
  {"name":"name selector, double quotes","selector":"$[\"a\"]","document":{"a":"A","b":"B"},"result":["A"]},
  {"name":"basic, no leading whitespace","selector":" $","invalid":true},
  {"name":"basic, no trailing whitespace","selector":"$ ","invalid":true},
  {"name":"basic, name shorthand, symbol","selector":"$.&","invalid":true},
  {"name":"basic, name shorthand, number","selector":"$.1","invalid":true},
  {"name":"basic, multiple selectors, space instead of comma","selector":"$[0 2]","invalid":true},
  {"name":"basic, selector, leading comma","selector":"$[,0]","invalid":true},
  {"name":"basic, selector, trailing comma","selector":"$[0,]","invalid":true},
  {"name":"basic, empty segment","selector":"$[]","invalid":true},
  {"name":"basic, bald descendant segment","selector":"$..","invalid":true},
  {"name":"basic, current node identifier without filter selector","selector":"$[@.a]","invalid":true},
  {"name":"basic, root node identifier in brackets without filter selector","selector":"$[$.a]","invalid":true},
  {"name":"filter, non-singular query in comparison, slice","selector":"$[?@[0:0]==0]","invalid":true}
];

function testCts() {
  var pass = 0, rej = 0, total = CTS.length, invs = 0;
  CTS.forEach(function (t) {
    if (t.invalid) {
      invs++;
      if (code(function () { jp.query(t.document || {}, t.selector); }) === "json-path/invalid") rej++;
      else check("cts invalid rejected: " + t.name, false);
      return;
    }
    var got;
    try { got = jp.query(t.document, t.selector); } catch (e) { check("cts query: " + t.name + " — " + e.message, false); return; }
    var ok = t.result !== undefined ? JSON.stringify(got) === JSON.stringify(t.result)
      : t.results.some(function (r) { return JSON.stringify(got) === JSON.stringify(r); });
    if (ok) pass++; else check("cts result: " + t.name + " got " + JSON.stringify(got).slice(0, 60), false);
  });
  var valid = total - invs;
  check("cts: all " + valid + " result cases match", pass === valid);
  check("cts: all " + invs + " invalid cases rejected", rej === invs);
}

function testFeatures() {
  var doc = { store: { book: [{ price: 8, title: "A" }, { price: 12, title: "B" }], bicycle: { price: 20 } } };
  check("wildcard", JSON.stringify(jp.query({ a: 1, b: 2 }, "$.*").sort()) === "[1,2]");
  check("slice", JSON.stringify(jp.query([0, 1, 2, 3, 4], "$[1:4]")) === "[1,2,3]");
  check("slice negative step", JSON.stringify(jp.query([0, 1, 2, 3], "$[::-1]")) === "[3,2,1,0]");
  check("descendant", JSON.stringify(jp.query(doc, "$..price").sort(function(a,c){return a-c;})) === "[8,12,20]");
  check("filter < ", JSON.stringify(jp.query(doc, "$.store.book[?@.price < 10].title")) === '["A"]');
  check("count() filter", JSON.stringify(jp.query({ a: { items: [1, 2, 3] } }, "$[?count(@.items[*]) == 3]")) === JSON.stringify([{ items: [1, 2, 3] }]));
  check("value() filter", JSON.stringify(jp.query({ x: { v: 5 } }, "$[?value(@.v) == 5]")) === JSON.stringify([{ v: 5 }]));
  check("existence", JSON.stringify(jp.query([{ a: 1 }, { b: 2 }], "$[?@.a]")) === JSON.stringify([{ a: 1 }]));
  // paths() normalized locations.
  check("paths()", JSON.stringify(jp.paths({ a: [{ p: 1 }, { p: 9 }] }, "$.a[?@.p > 5].p")) === JSON.stringify(["$['a'][1]['p']"]));
}

function testRegressionAndSafety() {
  // <= / >= include the equality case (RFC 9535 §2.3.5.2.2).
  check("<= null matches null", JSON.stringify(jp.query([{ a: null }, { a: 1 }], "$[?@.a<=null]")) === JSON.stringify([{ a: null }]));
  // length(Nothing) is Nothing, not 1 (the sentinel is an object).
  check("length(missing) is Nothing", JSON.stringify(jp.query([{ a: "ab" }, { c: "d" }], "$[?length(@.a)>0]")) === JSON.stringify([{ a: "ab" }]));
  check("b.jsonPath.JsonPathError thrown", code(function () { jp.query({}, "$["); }) === "json-path/invalid");
  // Deep descendant on a large doc stays bounded (no crash); sanity only.
  var big = {}; var cur = big; for (var i = 0; i < 50; i++) { cur.n = {}; cur = cur.n; }
  check("deep descendant does not crash", Array.isArray(jp.query(big, "$..n")));
}

function testSurface() {
  // Full b.jsonPath.* path references for the coverage gate.
  check("b.jsonPath.query is a function", typeof b.jsonPath.query === "function");
  check("b.jsonPath.paths is a function", typeof b.jsonPath.paths === "function");
  check("b.jsonPath.query selects a value", JSON.stringify(b.jsonPath.query({ a: 1 }, "$.a")) === "[1]");
  check("b.jsonPath.paths returns a normalized path", JSON.stringify(b.jsonPath.paths({ a: 1 }, "$.a")) === JSON.stringify(["$['a']"]));
  check("b.jsonPath.JsonPathError is the typed error", typeof b.jsonPath.JsonPathError === "function");
}

// Every malformed / adversarial path must be REFUSED with a typed error —
// never an uncaught crash and never a silent mis-evaluation.
function testMalformedRejected() {
  var bad = [
    // argument-type guard (not a parse error — a bad-arg refusal)
    { p: 123, doc: {}, want: "json-path/bad-arg", n: "non-string path" },
    { p: null, doc: {}, want: "json-path/bad-arg", n: "null path" },
    // structural parse failures
    { p: "a.b", want: "json-path/invalid", n: "missing root $" },
    { p: "$.a extra", want: "json-path/invalid", n: "trailing characters" },
    { p: "$[a]", want: "json-path/invalid", n: "bare unquoted name in bracket" },
    { p: "$[?]", want: "json-path/invalid", n: "empty filter" },
    { p: "$.", want: "json-path/invalid", n: "dot with no member" },
    { p: "$..", want: "json-path/invalid", n: "bald descendant" },
    { p: "$[1", want: "json-path/invalid", n: "unclosed bracket" },
    { p: "$['a", want: "json-path/invalid", n: "unterminated string" },
    // integer-token rules
    { p: "$[01]", want: "json-path/invalid", n: "leading zero index" },
    { p: "$[-0]", want: "json-path/invalid", n: "negative-zero index" },
    { p: "$[99999999999999999999]", want: "json-path/invalid", n: "index out of safe range" },
    // string-escape rules
    { p: "$['\\u12']", want: "json-path/invalid", n: "short \\u escape" },
    { p: "$['\\uD83D']", want: "json-path/invalid", n: "lone high surrogate" },
    { p: "$['\\x']", want: "json-path/invalid", n: "unknown escape" },
    { p: "$['a" + String.fromCharCode(1) + "b']", want: "json-path/invalid", n: "raw control char in string" },
    // number-literal rules inside filters
    { p: "$[?@.a==1.]", want: "json-path/invalid", n: "trailing dot in number" },
    { p: "$[?@.a==1e]", want: "json-path/invalid", n: "empty exponent" },
    // function well-typedness
    { p: "$[?bogus(@.a)]", want: "json-path/invalid", n: "unknown function" },
    { p: "$[?match(@.a)]", want: "json-path/invalid", n: "match arity (needs 2)" },
    { p: "$[?count('x')]", want: "json-path/invalid", n: "count nodes-arg type mismatch" },
    { p: "$[?length(@.a)]", want: "json-path/invalid", n: "value-func not a valid test" },
    { p: "$[?count(@.a) < length(@)]", want: null, n: "value funcs ARE comparable" }, // sanity control
    // non-singular query as a comparable
    { p: "$[?@.*==1]", want: "json-path/invalid", n: "wildcard (non-singular) in comparison" },
    { p: "$[?@..a==1]", want: "json-path/invalid", n: "descendant (non-singular) in comparison" },
  ];
  bad.forEach(function (t) {
    var got = code(function () { jp.query(t.doc || {}, t.p); });
    if (t.want === null) check("adversarial accepted: " + t.n, got === "NO-THROW");
    else check("adversarial refused (" + t.want + "): " + t.n, got === t.want);
  });
}

// Deeply-nested filter recursion must hit the typed DoS guard, not a raw
// V8 RangeError that escapes JsonPathError handling.
function testFilterDepthGuard() {
  var deep = "$[?" + Array(220).join("!") + "@.a]";
  check("over-deep filter → typed filter-too-deep", code(function () { jp.query({}, deep); }) === "json-path/filter-too-deep");
  var ok = "$[?" + Array(50).join("!") + "@.a]";
  check("moderately-nested filter still parses", Array.isArray(jp.query({ a: 1 }, ok)));
}

// Type-mismatch / out-of-range selections evaluate to an EMPTY nodelist
// (a well-typed no-match), never an error or a wrong value.
function testTypeAndRangeEdges() {
  check("name selector on array → empty", JSON.stringify(jp.query([1, 2, 3], "$.a")) === "[]");
  check("index selector on object → empty", JSON.stringify(jp.query({ a: 1 }, "$[0]")) === "[]");
  check("wildcard on scalar → empty", JSON.stringify(jp.query(5, "$.*")) === "[]");
  check("slice on non-array → empty", JSON.stringify(jp.query({ a: 1 }, "$[0:2]")) === "[]");
  check("descendant-wildcard on scalar → empty", JSON.stringify(jp.query(7, "$..*")) === "[]");
  check("positive index past end → empty", JSON.stringify(jp.query([1, 2], "$[9]")) === "[]");
  check("negative index past start → empty", JSON.stringify(jp.query([1, 2], "$[-9]")) === "[]");
  check("slice step 0 → empty", JSON.stringify(jp.query([1, 2, 3], "$[::0]")) === "[]");
  check("explicit-step slice", JSON.stringify(jp.query([0, 1, 2, 3, 4], "$[0:5:2]")) === "[0,2,4]");
  check("negative-start slice", JSON.stringify(jp.query([0, 1, 2, 3], "$[-2:]")) === "[2,3]");
  // Reading __proto__ as a name selector must not leak the prototype.
  check("__proto__ name selector reads nothing", JSON.stringify(jp.query({ a: 1 }, "$['__proto__']")) === "[]");
  // hostile match() pattern: invalid I-Regexp → no match, no crash.
  check("invalid regex in match() → no match, no throw", JSON.stringify(jp.query([{ a: "x" }], "$[?match(@.a, '(')]")) === "[]");
  check("match() anchors whole string", JSON.stringify(jp.query([{ a: "ab" }], "$[?match(@.a, 'a')]")) === "[]");
  check("search() is substring", JSON.stringify(jp.query([{ a: "zab" }], "$[?search(@.a, 'a')]")) === JSON.stringify([{ a: "zab" }]));
  check("match() on non-string field → no match", JSON.stringify(jp.query([{ a: 5 }], "$[?match(@.a, '5')]")) === "[]");
  // filter over object members; Nothing (missing @.a on z) compares false.
  check("filter over object members", JSON.stringify(jp.query({ x: { a: 1 }, y: { a: 1 }, z: { b: 2 } }, "$[?@.a == 1]")) === JSON.stringify([{ a: 1 }, { a: 1 }]));
}

// paths() must emit RFC-9535 normalized paths whose control characters are
// ESCAPED, so the location round-trips back through query().
function testNormalizedPathEscaping() {
  var doc = {}; doc["a\nb"] = 1;          // key containing a newline
  var p = jp.paths(doc, "$.*");
  check("newline key escaped (no raw \\n)", p[0].indexOf("\n") === -1);
  check("newline key emits \\n escape", p[0] === "$['a\\nb']");
  // The normalized path must round-trip: query at that location finds the node.
  check("normalized path round-trips", JSON.stringify(jp.query(doc, p[0])) === "[1]");

  var doc2 = {}; doc2["t\tq'x\\y"] = 2;   // tab, apostrophe, backslash together
  var p2 = jp.paths(doc2, "$.*");
  check("tab/quote/backslash all escaped", p2[0] === "$['t\\tq\\'x\\\\y']");
  check("mixed-escape path round-trips", JSON.stringify(jp.query(doc2, p2[0])) === "[2]");

  var doc3 = {}; doc3[String.fromCharCode(1)] = 3;   // generic control char -> XXXX
  var p3 = jp.paths(doc3, "$.*");
  check("control char emits \\u escape", p3[0] === "$['\\u0001']");
  check("control-char path round-trips", JSON.stringify(jp.query(doc3, p3[0])) === "[3]");
}

// Parser branches: bracket/paren/int-token error paths and the filter
// well-typedness rejections that only fire on malformed function/comparison
// syntax.
function testParserErrorBranches() {
  // Unterminated filter group: eat(')') fails on the closing ']'.
  check("filter group missing ')' → invalid", code(function () { jp.query({}, "$[?(@.a==1]"); }) === "json-path/invalid");
  // Bare '-' with no digit: parseIntToken "expected integer".
  check("lone '-' index → invalid", code(function () { jp.query([], "$[-]"); }) === "json-path/invalid");
  // Non-digit interrupting an index token: the slice-detection loop breaks,
  // then the bracket close is missing.
  check("index followed by letter → invalid", code(function () { jp.query([], "$[1x]"); }) === "json-path/invalid");
  // High surrogate followed by a NON-low escape: "invalid surrogate pair".
  check("high surrogate + non-low escape → invalid", code(function () { jp.query({}, "$['\\uD83D\\u0041']"); }) === "json-path/invalid");
  // Function-argument dispatch: a logical arg (parsed, then rejected by the
  // value-typed parameter check) and an unrecognized argument token.
  check("logical function arg → type mismatch", code(function () { jp.query({}, "$[?match(!@.a, 'x')]"); }) === "json-path/invalid");
  check("garbage function arg → invalid", code(function () { jp.query({}, "$[?match(@.a, ~)]"); }) === "json-path/invalid");
  // Non-singular query passed where a ValueType arg is required.
  check("length(non-singular) → type mismatch", code(function () { jp.query({}, "$[?length(@.*)==1]"); }) === "json-path/invalid");
  // A logical-returning function used as a comparison operand.
  check("logical function as comparable → invalid", code(function () { jp.query({}, "$[?match(@.a,'x')==true]"); }) === "json-path/invalid");
  // A bare value literal is not a valid test-expression.
  check("bare number as filter test → invalid", code(function () { jp.query({}, "$[?42]"); }) === "json-path/invalid");
}

// Descendant segment with a bracketed selector (`$..[...]`), and the string
// escapes / \uXXXX forms that name selectors accept.
function testDescendantBracketAndEscapes() {
  var doc = { a: 1, b: { a: 2, c: { a: 3 } } };
  check("descendant bracket selector", eq(jp.query(doc, "$..['a']"), [1, 2, 3]));

  var dR = {}; dR["x\ry"] = 1;
  check("\\r escape in name", eq(jp.query(dR, "$['x\\ry']"), [1]));
  var dB = {}; dB["x\by"] = 1;
  check("\\b escape in name", eq(jp.query(dB, "$['x\\by']"), [1]));
  var dF = {}; dF["x\fy"] = 1;
  check("\\f escape in name", eq(jp.query(dF, "$['x\\fy']"), [1]));
  var dSlash = {}; dSlash["x/y"] = 1;
  check("\\/ escape in name", eq(jp.query(dSlash, "$['x\\/y']"), [1]));

  var dU = {}; dU["A"] = 1;
  check("BMP \\u escape decodes", eq(jp.query(dU, "$['\\u0041']"), [1]));
  var dEmoji = {}; dEmoji["\uD83D\uDE00"] = 7;   // U+1F600 as a surrogate pair
  check("surrogate-pair \\u escape decodes", eq(jp.query(dEmoji, "$['\\uD83D\\uDE00']"), [7]));
}

// Filter-expression evaluation: paren grouping with ||, the `false` literal,
// number-literal forms, root ($) sub-queries, `!=`, and singular index
// queries against non-array / out-of-range operands.
function testFilterExprBranches() {
  check("paren group with ||", eq(jp.query([{ a: 1 }, { b: 2 }, { c: 3 }], "$[?(@.a || @.b)]"), [{ a: 1 }, { b: 2 }]));
  check("false literal compare", eq(jp.query([{ a: false }, { a: true }, { a: 0 }], "$[?@.a==false]"), [{ a: false }]));

  // Number-literal parsing: sign, zero, fraction, exponent (e/E, signed).
  check("negative number literal", eq(jp.query([{ a: -5 }, { a: 5 }], "$[?@.a==-5]"), [{ a: -5 }]));
  check("zero literal", eq(jp.query([{ a: 0 }, { a: 1 }], "$[?@.a==0]"), [{ a: 0 }]));
  check("fraction literal", eq(jp.query([{ a: 1.5 }, { a: 1 }], "$[?@.a==1.5]"), [{ a: 1.5 }]));
  check("exponent literal (e)", eq(jp.query([{ a: 100 }, { a: 10 }], "$[?@.a==1e2]"), [{ a: 100 }]));
  check("exponent literal (E)", eq(jp.query([{ a: 100 }], "$[?@.a==1E2]"), [{ a: 100 }]));
  check("fraction+exponent literal", eq(jp.query([{ a: 15 }, { a: 1 }], "$[?@.a==1.5e1]"), [{ a: 15 }]));
  check("negative-exponent literal", eq(jp.query([{ a: 1.5 }], "$[?@.a==15e-1]"), [{ a: 1.5 }]));

  // Root ($) singular query as a comparable and as an existence test.
  check("$-root singular query in comparison", eq(jp.query({ t: 5, arr: [{ v: 3 }, { v: 9 }] }, "$.arr[?@.v > $.t]"), [{ v: 9 }]));
  check("$-root existence test", eq(jp.query({ flag: true, items: [1, 2] }, "$.items[?$.flag]"), [1, 2]));

  // `!=` comparison.
  check("!= comparison", eq(jp.query([{ a: 1 }, { a: 2 }], "$[?@.a!=1]"), [{ a: 2 }]));

  // Singular index query: non-array operand → Nothing; negative index; and
  // out-of-range index → Nothing.
  check("index singular on non-array → Nothing (no match)", eq(jp.query([[1, 5], { x: 9 }, [7]], "$[?@[-1]==5]"), [[1, 5]]));
  check("index singular out of range → Nothing", eq(jp.query([[0]], "$[?@[5]==0]"), []));
}

// _deepEqual over composite values via `==` in a filter.
function testDeepEqual() {
  check("deepEqual arrays equal", eq(jp.query([{ a: [1, 2], b: [1, 2] }], "$[?@.a==@.b]"), [{ a: [1, 2], b: [1, 2] }]));
  check("deepEqual arrays length differ", eq(jp.query([{ a: [1], b: [1, 2] }], "$[?@.a==@.b]"), []));
  check("deepEqual array vs object type mismatch", eq(jp.query([{ a: [1], b: { "0": 1 } }], "$[?@.a==@.b]"), []));
  check("deepEqual objects equal", eq(jp.query([{ a: { x: 1 }, b: { x: 1 } }], "$[?@.a==@.b]"), [{ a: { x: 1 }, b: { x: 1 } }]));
  check("deepEqual objects key-count differ", eq(jp.query([{ a: { x: 1 }, b: { x: 1, y: 2 } }], "$[?@.a==@.b]"), []));
  check("deepEqual objects missing key", eq(jp.query([{ a: { x: 1 }, b: { y: 1 } }], "$[?@.a==@.b]"), []));
  check("deepEqual objects value differ", eq(jp.query([{ a: { x: 1 }, b: { x: 2 } }], "$[?@.a==@.b]"), []));
}

// Function-extension results: length over array/object/scalar, value() over
// multi/single nodelists, a nested value() as a match() argument, and the
// I-Regexp escape/character-class translation paths.
function testFunctionResults() {
  check("length of array", eq(jp.query([{ a: [1, 2, 3] }], "$[?length(@.a)==3]"), [{ a: [1, 2, 3] }]));
  check("length of object", eq(jp.query([{ a: { x: 1, y: 2 } }], "$[?length(@.a)==2]"), [{ a: { x: 1, y: 2 } }]));
  check("length of scalar → Nothing", eq(jp.query([{ a: 5 }], "$[?length(@.a)==1]"), []));
  check("value() of multi-node → Nothing", eq(jp.query([{ a: [1, 2] }], "$[?value(@.a[*])==1]"), []));
  // Nested value() feeding match(): exercises func-typed function arguments.
  check("nested value() as match() input", eq(jp.query([{ a: "xyz" }], "$[?match(value(@.a), 'x.*')]"), [{ a: "xyz" }]));
  // I-Regexp escape (\.) and character class ([0-9]) pass-through.
  check("match() escaped-dot pattern", eq(jp.query([{ a: "a.c" }, { a: "axc" }], "$[?match(@.a, 'a\\\\.c')]"), [{ a: "a.c" }]));
  check("match() character-class pattern", eq(jp.query([{ a: "123" }, { a: "abc" }], "$[?match(@.a, '[0-9]+')]"), [{ a: "123" }]));
}

// Slice bounds math: negative / over-length start & end clamping, in both
// step directions.
function testSliceBounds() {
  var arr = [0, 1, 2, 3, 4];
  check("slice start below 0 clamps to 0", eq(jp.query(arr, "$[-100:3]"), [0, 1, 2]));
  check("slice end over length clamps to length", eq(jp.query(arr, "$[2:100]"), [2, 3, 4]));
  check("slice negative end", eq(jp.query(arr, "$[:-2]"), [0, 1, 2]));
  check("negative-step positive bounds", eq(jp.query(arr, "$[4:0:-1]"), [4, 3, 2, 1]));
  check("negative-step negative bounds", eq(jp.query(arr, "$[-1:-4:-1]"), [4, 3, 2]));
}

// DoS ceilings: a descendant walk exceeding the per-walk node cap, and a
// chained wildcard cross-product exceeding the running-nodelist cap. Both
// use shared array references so the DOCUMENT stays tiny while the traversal
// genuinely crosses 1,000,000 nodes (the cap is not lowered).
function testNodeCaps() {
  var innerD = new Array(1001);
  for (var i = 0; i < innerD.length; i++) innerD[i] = i;
  var rootD = new Array(1001);
  for (var j = 0; j < rootD.length; j++) rootD[j] = innerD;
  check("descendant walk over node cap → too-large", code(function () { jp.query(rootD, "$..*"); }) === "json-path/too-large");

  var innerN = new Array(1001);
  for (var k = 0; k < innerN.length; k++) innerN[k] = k;
  var rootN = new Array(1001);
  for (var m = 0; m < rootN.length; m++) rootN[m] = innerN;
  check("chained-selector nodelist over cap → too-large", code(function () { jp.query(rootN, "$[*][*]"); }) === "json-path/too-large");
}

// paths() must escape \b \f \r in normalized-path names, round-tripping
// through query().
function testMoreNormalizedPathEscaping() {
  var dB = {}; dB["a\bb"] = 1;
  var pB = jp.paths(dB, "$.*");
  check("backspace key emits \\b escape", pB[0] === "$['a\\bb']");
  check("backspace path round-trips", eq(jp.query(dB, pB[0]), [1]));

  var dF = {}; dF["a\fb"] = 2;
  var pF = jp.paths(dF, "$.*");
  check("formfeed key emits \\f escape", pF[0] === "$['a\\fb']");
  check("formfeed path round-trips", eq(jp.query(dF, pF[0]), [2]));

  var dR = {}; dR["a\rb"] = 3;
  var pR = jp.paths(dR, "$.*");
  check("carriage-return key emits \\r escape", pR[0] === "$['a\\rb']");
  check("carriage-return path round-trips", eq(jp.query(dR, pR[0]), [3]));
}

function testFunctionArgLiterals() {
  // Literal function arguments — number / true / false / null — are parsed
  // by parseFunctionArg, a distinct path from comparison-operand literals.
  check("fn arg: numeric literal parses", eq(jp.query([{}], "$[?length(42) == 0]"), []));
  check("fn arg: true literal parses", eq(jp.query([{}], "$[?match(true, \"x\")]"), []));
  check("fn arg: false literal parses", eq(jp.query([{}], "$[?match(false, \"x\")]"), []));
  check("fn arg: null literal parses", eq(jp.query([{}], "$[?match(null, \"x\")]"), []));
  // count() takes a nodes-typed argument (a non-singular query).
  check("fn arg: nodes-typed argument to count()",
        eq(jp.query([{ a: [1, 2, 3] }], "$[?count(@.a[*]) == 3]"), [{ a: [1, 2, 3] }]));
  // A '-' not followed by a digit is an invalid number literal.
  var threw = false;
  try { jp.query([], "$[?@.a > -]"); } catch (_e) { threw = true; }
  check("malformed number literal ('-' with no digit) rejected", threw);
}

async function run() {
  testSurface();
  testCts();
  testFeatures();
  testRegressionAndSafety();
  testMalformedRejected();
  testFilterDepthGuard();
  testTypeAndRangeEdges();
  testNormalizedPathEscaping();
  testParserErrorBranches();
  testDescendantBracketAndEscapes();
  testFilterExprBranches();
  testDeepEqual();
  testFunctionResults();
  testSliceBounds();
  testNodeCaps();
  testMoreNormalizedPathEscaping();
  testFunctionArgLiterals();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[json-path] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
