// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Layer 0 — b.jsonMergePatch (RFC 7396 JSON Merge Patch).
 * Oracle: every test case from RFC 7396 Appendix A (target + patch →
 * result), plus immutability and prototype-pollution checks.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;
var jmp = b.jsonMergePatch;
function eq(a, c) { return b.canonicalJson.stringify(a) === b.canonicalJson.stringify(c); }
function code(fn) { try { fn(); return "NO-THROW"; } catch (e) { return e.code; } }

// RFC 7396 Appendix A example test cases.
var CASES = [
  { original: { a: "b" }, patch: { a: "c" }, result: { a: "c" } },
  { original: { a: "b" }, patch: { b: "c" }, result: { a: "b", b: "c" } },
  { original: { a: "b" }, patch: { a: null }, result: {} },
  { original: { a: "b", b: "c" }, patch: { a: null }, result: { b: "c" } },
  { original: { a: ["b"] }, patch: { a: "c" }, result: { a: "c" } },
  { original: { a: "c" }, patch: { a: ["b"] }, result: { a: ["b"] } },
  { original: { a: { b: "c" } }, patch: { a: { b: "d", c: null } }, result: { a: { b: "d" } } },
  { original: { a: [{ b: "c" }] }, patch: { a: [1] }, result: { a: [1] } },
  { original: ["a", "b"], patch: ["c", "d"], result: ["c", "d"] },
  { original: { a: "b" }, patch: ["c"], result: ["c"] },
  { original: { a: "foo" }, patch: null, result: null },
  { original: { a: "foo" }, patch: "bar", result: "bar" },
  { original: { e: null }, patch: { a: 1 }, result: { e: null, a: 1 } },
  { original: [1, 2], patch: { a: "b", c: null }, result: { a: "b" } },
  { original: {}, patch: { a: { bb: { ccc: null } } }, result: { a: { bb: {} } } },
];

function testSurface() {
  check("b.jsonMergePatch.merge is a function", typeof jmp.merge === "function");
}

function testRfc7396Conformance() {
  var pass = 0;
  CASES.forEach(function (c, i) {
    var got = jmp.merge(c.original, c.patch);
    if (eq(got, c.result)) pass++;
    else check("RFC 7396 case #" + (i + 1) + " got " + JSON.stringify(got), false);
  });
  check("RFC 7396 Appendix A: all " + CASES.length + " cases match", pass === CASES.length);
}

function testImmutableAndSafe() {
  var orig = { a: "b", c: { d: "e" } };
  var out = jmp.merge(orig, { a: "z", c: { d: null, f: 1 } });
  check("merge: result is correct", eq(out, { a: "z", c: { f: 1 } }));
  check("merge: target is not mutated", eq(orig, { a: "b", c: { d: "e" } }));

  // Prototype pollution: a "__proto__" member is a literal own key.
  var poll = jmp.merge({}, JSON.parse('{"__proto__":{"polluted":true}}'));
  check("merge: __proto__ is a literal own key", Object.prototype.hasOwnProperty.call(poll, "__proto__"));
  check("merge: Object.prototype not polluted", ({}).polluted === undefined);

  // Nested __proto__ merge does not pollute.
  jmp.merge({}, JSON.parse('{"x":{"__proto__":{"polluted":true}}}'));
  check("merge: nested __proto__ does not pollute", ({}).polluted === undefined);

  // undefined patch refused (null is the explicit "replace with null").
  check("merge: undefined patch refused", code(function () { jmp.merge({ a: 1 }); }) === "json-merge-patch/bad-patch");
  check("b.jsonMergePatch.JsonMergePatchError is the typed error", typeof jmp.JsonMergePatchError === "function");
}

async function run() {
  testSurface();
  testRfc7396Conformance();
  testImmutableAndSafe();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[json-merge-patch] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
