"use strict";
/**
 * Layer 0 — b.jsonPointer (RFC 6901) + b.jsonPatch (RFC 6902).
 * The oracle is the official json-patch/json-patch-tests conformance
 * suite (every enabled case with an expected result or error) plus the
 * RFC 6901 §5 pointer-evaluation examples.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
function code(fn){try{fn();return "NO-THROW";}catch(e){return e.code||"THREW";}}
function eq(a,c){return b.canonicalJson.stringify(a)===b.canonicalJson.stringify(c);}

// Official json-patch-tests conformance cases (doc + patch + expected|error).
var PATCH_CASES = [
  {"doc":{},"patch":[],"expected":{}},
  {"doc":{"foo":1},"patch":[],"expected":{"foo":1}},
  {"doc":{"foo":1,"bar":2},"patch":[],"expected":{"bar":2,"foo":1}},
  {"doc":[{"foo":1,"bar":2}],"patch":[],"expected":[{"bar":2,"foo":1}]},
  {"doc":{"foo":{"foo":1,"bar":2}},"patch":[],"expected":{"foo":{"bar":2,"foo":1}}},
  {"doc":{"foo":null},"patch":[{"op":"add","path":"/foo","value":1}],"expected":{"foo":1}},
  {"doc":[],"patch":[{"op":"add","path":"/0","value":"foo"}],"expected":["foo"]},
  {"doc":["foo"],"patch":[],"expected":["foo"]},
  {"doc":{},"patch":[{"op":"add","path":"/foo","value":"1"}],"expected":{"foo":"1"}},
  {"doc":{},"patch":[{"op":"add","path":"/foo","value":1}],"expected":{"foo":1}},
  {"doc":{},"patch":[{"op":"add","path":"","value":[]}],"expected":[]},
  {"doc":[],"patch":[{"op":"add","path":"","value":{}}],"expected":{}},
  {"doc":[],"patch":[{"op":"add","path":"/-","value":"hi"}],"expected":["hi"]},
  {"doc":{},"patch":[{"op":"add","path":"/","value":1}],"expected":{"":1}},
  {"doc":{"foo":{}},"patch":[{"op":"add","path":"/foo/","value":1}],"expected":{"foo":{"":1}}},
  {"doc":{"foo":1},"patch":[{"op":"add","path":"/bar","value":[1,2]}],"expected":{"foo":1,"bar":[1,2]}},
  {"doc":{"foo":1,"baz":[{"qux":"hello"}]},"patch":[{"op":"add","path":"/baz/0/foo","value":"world"}],"expected":{"foo":1,"baz":[{"qux":"hello","foo":"world"}]}},
  {"doc":{"bar":[1,2]},"patch":[{"op":"add","path":"/bar/8","value":"5"}],"error":true},
  {"doc":{"bar":[1,2]},"patch":[{"op":"add","path":"/bar/-1","value":"5"}],"error":true},
  {"doc":{"foo":1},"patch":[{"op":"add","path":"/bar","value":true}],"expected":{"foo":1,"bar":true}},
  {"doc":{"foo":1},"patch":[{"op":"add","path":"/bar","value":false}],"expected":{"foo":1,"bar":false}},
  {"doc":{"foo":1},"patch":[{"op":"add","path":"/bar","value":null}],"expected":{"foo":1,"bar":null}},
  {"doc":{"foo":1},"patch":[{"op":"add","path":"/0","value":"bar"}],"expected":{"0":"bar","foo":1}},
  {"doc":["foo"],"patch":[{"op":"add","path":"/1","value":"bar"}],"expected":["foo","bar"]},
  {"doc":["foo","sil"],"patch":[{"op":"add","path":"/1","value":"bar"}],"expected":["foo","bar","sil"]},
  {"doc":["foo","sil"],"patch":[{"op":"add","path":"/0","value":"bar"}],"expected":["bar","foo","sil"]},
  {"doc":["foo","sil"],"patch":[{"op":"add","path":"/2","value":"bar"}],"expected":["foo","sil","bar"]},
  {"doc":["foo","sil"],"patch":[{"op":"add","path":"/3","value":"bar"}],"error":true},
  {"doc":{"1e0":"foo"},"patch":[{"op":"test","path":"/1e0","value":"foo"}],"expected":{"1e0":"foo"}},
  {"doc":["foo","bar"],"patch":[{"op":"test","path":"/1e0","value":"bar"}],"error":true},
  {"doc":["foo","sil"],"patch":[{"op":"add","path":"/bar","value":42}],"error":true},
  {"doc":["foo","sil"],"patch":[{"op":"add","path":"/1","value":["bar","baz"]}],"expected":["foo",["bar","baz"],"sil"]},
  {"doc":{"foo":1,"bar":[1,2,3,4]},"patch":[{"op":"remove","path":"/bar"}],"expected":{"foo":1}},
  {"doc":{"foo":1,"baz":[{"qux":"hello"}]},"patch":[{"op":"remove","path":"/baz/0/qux"}],"expected":{"foo":1,"baz":[{}]}},
  {"doc":{"foo":1,"baz":[{"qux":"hello"}]},"patch":[{"op":"replace","path":"/foo","value":[1,2,3,4]}],"expected":{"foo":[1,2,3,4],"baz":[{"qux":"hello"}]}},
  {"doc":{"foo":[1,2,3,4],"baz":[{"qux":"hello"}]},"patch":[{"op":"replace","path":"/baz/0/qux","value":"world"}],"expected":{"foo":[1,2,3,4],"baz":[{"qux":"world"}]}},
  {"doc":["foo"],"patch":[{"op":"replace","path":"/0","value":"bar"}],"expected":["bar"]},
  {"doc":[""],"patch":[{"op":"replace","path":"/0","value":0}],"expected":[0]},
  {"doc":[""],"patch":[{"op":"replace","path":"/0","value":true}],"expected":[true]},
  {"doc":[""],"patch":[{"op":"replace","path":"/0","value":false}],"expected":[false]},
  {"doc":[""],"patch":[{"op":"replace","path":"/0","value":null}],"expected":[null]},
  {"doc":["foo","sil"],"patch":[{"op":"replace","path":"/1","value":["bar","baz"]}],"expected":["foo",["bar","baz"]]},
  {"doc":{"foo":"bar"},"patch":[{"op":"replace","path":"","value":{"baz":"qux"}}],"expected":{"baz":"qux"}},
  {"doc":{"bar":"baz"},"patch":[{"op":"replace","path":"/foo/bar","value":false}],"error":true},
  {"doc":{"foo":1},"patch":[{"op":"test","path":"/foo","value":1,"spurious":1}],"expected":{"foo":1}},
  {"doc":{"foo":null},"patch":[{"op":"test","path":"/foo","value":null}],"expected":{"foo":null}},
  {"doc":{"foo":null},"patch":[{"op":"replace","path":"/foo","value":"truthy"}],"expected":{"foo":"truthy"}},
  {"doc":{"foo":null},"patch":[{"op":"move","from":"/foo","path":"/bar"}],"expected":{"bar":null}},
  {"doc":{"foo":null},"patch":[{"op":"copy","from":"/foo","path":"/bar"}],"expected":{"foo":null,"bar":null}},
  {"doc":{"foo":null},"patch":[{"op":"remove","path":"/foo"}],"expected":{}},
  {"doc":{"foo":"bar"},"patch":[{"op":"replace","path":"/foo","value":null}],"expected":{"foo":null}},
  {"doc":{"foo":{"foo":1,"bar":2}},"patch":[{"op":"test","path":"/foo","value":{"bar":2,"foo":1}}],"expected":{"foo":{"foo":1,"bar":2}}},
  {"doc":{"foo":[{"foo":1,"bar":2}]},"patch":[{"op":"test","path":"/foo","value":[{"bar":2,"foo":1}]}],"expected":{"foo":[{"foo":1,"bar":2}]}},
  {"doc":{"foo":{"bar":[1,2,5,4]}},"patch":[{"op":"test","path":"/foo","value":{"bar":[1,2,5,4]}}],"expected":{"foo":{"bar":[1,2,5,4]}}},
  {"doc":{"foo":{"bar":[1,2,5,4]}},"patch":[{"op":"test","path":"/foo","value":[1,2]}],"error":true},
  {"doc":{"":1},"patch":[{"op":"test","path":"/","value":1}],"expected":{"":1}},
  {"doc":{"foo":["bar","baz"],"":0,"a/b":1,"c%d":2,"e^f":3,"g|h":4,"i\\j":5,"k\"l":6," ":7,"m~n":8},"patch":[{"op":"test","path":"/foo","value":["bar","baz"]},{"op":"test","path":"/foo/0","value":"bar"},{"op":"test","path":"/","value":0},{"op":"test","path":"/a~1b","value":1},{"op":"test","path":"/c%d","value":2},{"op":"test","path":"/e^f","value":3},{"op":"test","path":"/g|h","value":4},{"op":"test","path":"/i\\j","value":5},{"op":"test","path":"/k\"l","value":6},{"op":"test","path":"/ ","value":7},{"op":"test","path":"/m~0n","value":8}],"expected":{"":0," ":7,"a/b":1,"c%d":2,"e^f":3,"foo":["bar","baz"],"g|h":4,"i\\j":5,"k\"l":6,"m~n":8}},
  {"doc":{"foo":1},"patch":[{"op":"move","from":"/foo","path":"/foo"}],"expected":{"foo":1}},
  {"doc":{"foo":1,"baz":[{"qux":"hello"}]},"patch":[{"op":"move","from":"/foo","path":"/bar"}],"expected":{"baz":[{"qux":"hello"}],"bar":1}},
  {"doc":{"baz":[{"qux":"hello"}],"bar":1},"patch":[{"op":"move","from":"/baz/0/qux","path":"/baz/1"}],"expected":{"baz":[{},"hello"],"bar":1}},
  {"doc":{"baz":[{"qux":"hello"}],"bar":1},"patch":[{"op":"copy","from":"/baz/0","path":"/boo"}],"expected":{"baz":[{"qux":"hello"}],"bar":1,"boo":{"qux":"hello"}}},
  {"doc":{"foo":"bar"},"patch":[{"op":"add","path":"","value":{"baz":"qux"}}],"expected":{"baz":"qux"}},
  {"doc":[1,2],"patch":[{"op":"add","path":"/-","value":{"foo":["bar","baz"]}}],"expected":[1,2,{"foo":["bar","baz"]}]},
  {"doc":[1,2,[3,[4,5]]],"patch":[{"op":"add","path":"/2/1/-","value":{"foo":["bar","baz"]}}],"expected":[1,2,[3,[4,5,{"foo":["bar","baz"]}]]]},
  {"doc":{"foo":1,"baz":[{"qux":"hello"}]},"patch":[{"op":"remove","path":"/baz/1e0/qux"}],"error":true},
  {"doc":[1,2,3,4],"patch":[{"op":"remove","path":"/0"}],"expected":[2,3,4]},
  {"doc":[1,2,3,4],"patch":[{"op":"remove","path":"/1"},{"op":"remove","path":"/2"}],"expected":[1,3]},
  {"doc":[1,2,3,4],"patch":[{"op":"remove","path":"/1e0"}],"error":true},
  {"doc":[""],"patch":[{"op":"replace","path":"/1e0","value":false}],"error":true},
  {"doc":{"baz":[1,2,3],"bar":1},"patch":[{"op":"copy","from":"/baz/1e0","path":"/boo"}],"error":true},
  {"doc":{"foo":1,"baz":[1,2,3,4]},"patch":[{"op":"move","from":"/baz/1e0","path":"/foo"}],"error":true},
  {"doc":["foo","sil"],"patch":[{"op":"add","path":"/1e0","value":"bar"}],"error":true},
  {"doc":{},"patch":[{"op":"add","value":"bar"}],"error":true},
  {"doc":{},"patch":[{"op":"add","path":null,"value":"bar"}],"error":true},
  {"doc":{},"patch":[{"op":"add","path":"foo","value":"bar"}],"error":true},
  {"doc":[1],"patch":[{"op":"add","path":"/-"}],"error":true},
  {"doc":[1],"patch":[{"op":"replace","path":"/0"}],"error":true},
  {"doc":[null],"patch":[{"op":"test","path":"/0"}],"error":true},
  {"doc":[false],"patch":[{"op":"test","path":"/0"}],"error":true},
  {"doc":[1],"patch":[{"op":"copy","path":"/-"}],"error":true},
  {"doc":{"foo":1},"patch":[{"op":"copy","from":"/bar","path":"/foo"}],"error":true},
  {"doc":{"foo":1},"patch":[{"op":"move","path":""}],"error":true},
  {"doc":{"foo":1},"patch":[{"op":"move","from":"/bar","path":"/foo"}],"error":true},
  {"doc":{"foo":1},"patch":[{"op":"spam","path":"/foo","value":1}],"error":true},
  {"doc":["foo","bar"],"patch":[{"op":"test","path":"/00","value":"foo"}],"error":true},
  {"doc":["foo","bar"],"patch":[{"op":"test","path":"/01","value":"bar"}],"error":true},
  {"doc":{"foo":"bar"},"patch":[{"op":"remove","path":"/baz"}],"error":true},
  {"doc":{"foo":"bar"},"patch":[{"op":"remove","path":"/missing1/missing2"}],"error":true},
  {"doc":["foo","bar"],"patch":[{"op":"remove","path":"/2"}],"error":true},
  {"doc":{"foo":"bar"},"patch":[{"op":"add","path":"/FOO","value":"BAR"}],"expected":{"foo":"bar","FOO":"BAR"}},
  {"doc":{"foo":{"bar":{"baz":[{"boo":"net"}]}}},"patch":[{"op":"copy","from":"/foo","path":"/bak"},{"op":"replace","path":"/bak/bar/baz/0/boo","value":"qux"}],"expected":{"foo":{"bar":{"baz":[{"boo":"net"}]}},"bak":{"bar":{"baz":[{"boo":"qux"}]}}}},
  {"doc":{"foo":{"bar":{"baz":[{"boo":"net"}]}}},"patch":[{"op":"copy","from":"/foo","path":"/bak"},{"op":"replace","path":"/foo/bar/baz/0/boo","value":"qux"}],"expected":{"foo":{"bar":{"baz":[{"boo":"qux"}]}},"bak":{"bar":{"baz":[{"boo":"net"}]}}}}
];


function testPointer() {
  // RFC 6901 §5 worked examples.
  var doc = { "foo": ["bar", "baz"], "": 0, "a/b": 1, "c%d": 2, "e^f": 3, "g|h": 4, "i\\j": 5, "k\"l": 6, " ": 7, "m~n": 8 };
  check("pointer: whole doc", b.jsonPointer.get(doc, "") === doc);
  check("pointer: /foo array", b.jsonPointer.get(doc, "/foo").length === 2);
  check("pointer: /foo/0", b.jsonPointer.get(doc, "/foo/0") === "bar");
  check("pointer: / empty key", b.jsonPointer.get(doc, "/") === 0);
  check("pointer: /a~1b slash escape", b.jsonPointer.get(doc, "/a~1b") === 1);
  check("pointer: /m~0n tilde escape", b.jsonPointer.get(doc, "/m~0n") === 8);
  check("pointer: /c%d literal", b.jsonPointer.get(doc, "/c%d") === 2);
  check("pointer: parse decodes tokens", b.jsonPointer.parse("/a~1b/m~0n").join() === "a/b,m~n");
  check("pointer: not-found throws", code(function(){ b.jsonPointer.get(doc, "/nope"); }) === "json-pointer/not-found");
  check("pointer: non-/ start refused", code(function(){ b.jsonPointer.get(doc, "foo"); }) === "json-pointer/bad-pointer");
  check("pointer: leading-zero index not-found", code(function(){ b.jsonPointer.get({a:[1]}, "/a/01"); }) === "json-pointer/not-found");
}

function testPatchConformance() {
  var pass = 0, errs = 0;
  PATCH_CASES.forEach(function (c, i) {
    if (c.error) {
      var threw = false;
      try { b.jsonPatch.apply(c.doc, c.patch); } catch (_e) { threw = true; }
      if (threw) errs++; else check("patch error case rejected #" + i + " " + JSON.stringify(c.patch).slice(0,60), false);
      return;
    }
    var got;
    try { got = b.jsonPatch.apply(c.doc, c.patch); } catch (e) { check("patch applies #" + i + ": " + e.message, false); return; }
    if (eq(got, c.expected)) pass++; else check("patch result #" + i + " " + JSON.stringify(c.patch).slice(0,60) + " got " + JSON.stringify(got).slice(0,80), false);
  });
  var expectPass = PATCH_CASES.filter(function (c) { return !c.error; }).length;
  var expectErr = PATCH_CASES.filter(function (c) { return c.error; }).length;
  check("RFC 6902 conformance: all " + expectPass + " result cases match", pass === expectPass);
  check("RFC 6902 conformance: all " + expectErr + " error cases rejected", errs === expectErr);
}

function testAtomic() {
  // A failing op leaves the original document untouched.
  var orig = { a: 1, b: 2 };
  try { b.jsonPatch.apply(orig, [{ op: "remove", path: "/a" }, { op: "test", path: "/b", value: 999 }]); } catch (_e) { /* expected */ }
  check("patch: original doc untouched on failure", orig.a === 1 && orig.b === 2);
  check("b.jsonPatch.JsonPatchError thrown", code(function(){ b.jsonPatch.apply({}, [{op:"bogus",path:"/x"}]); }) === "json-patch/bad-op");
  check("b.jsonPointer.JsonPointerError exists", typeof b.jsonPointer.JsonPointerError === "function" && typeof b.jsonPatch.OPS === "object" && typeof b.jsonPointer.ARRAY_INDEX_RE.test === "function");
}

function testSecurity() {
  // Prototype pollution: add /__proto__ must create a literal own key, not
  // touch the prototype.
  var polluted = b.jsonPatch.apply({}, [{ op: "add", path: "/__proto__", value: { polluted: true } }]);
  check("patch: /__proto__ becomes a literal own key", Object.prototype.hasOwnProperty.call(polluted, "__proto__") && polluted.polluted === undefined);
  check("patch: Object.prototype not polluted", ({}).polluted === undefined);
  // Nested __proto__ traversal is blocked (no own __proto__ to descend).
  check("patch: descend through __proto__ refused", code(function () { b.jsonPatch.apply({}, [{ op: "add", path: "/__proto__/polluted", value: true }]); }) === "json-patch/path-not-found");
  check("patch: Object.prototype still clean after nested attempt", ({}).polluted === undefined);
  // Invalid tilde escapes are rejected.
  check("pointer: invalid ~ escape (~2) refused", code(function () { b.jsonPointer.get({ x: 1 }, "/~2"); }) === "json-pointer/bad-pointer");
  check("pointer: trailing ~ refused", code(function () { b.jsonPointer.get({ x: 1 }, "/foo~"); }) === "json-pointer/bad-pointer");
}

async function run() {
  testPointer();
  testPatchConformance();
  testAtomic();
  testSecurity();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[json-patch] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
