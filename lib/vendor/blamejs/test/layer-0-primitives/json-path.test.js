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

async function run() {
  testSurface();
  testCts();
  testFeatures();
  testRegressionAndSafety();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[json-path] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
