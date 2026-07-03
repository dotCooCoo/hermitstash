// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Test the test-helper itself: assertJsonRoundTrip catches the bug
 * classes Codex flagged across v0.9.19-v0.9.21 (function ref / Date /
 * Buffer / Symbol / BigInt / cycle).
 */

var helpers = require("../helpers");
var check   = helpers.check;
var { assertJsonRoundTrip } = require("../helpers/json-round-trip");

function expectThrows(label, fn, messageMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && threw.message.indexOf(messageMatch) !== -1);
}

function testHappyPath() {
  assertJsonRoundTrip({ a: 1, b: "x", c: [1, 2], d: { nested: true } }, "plain shape");
  assertJsonRoundTrip(null, "null");
  assertJsonRoundTrip([1, 2, 3], "array");
  assertJsonRoundTrip("string", "string");
  assertJsonRoundTrip(42, "number");
  assertJsonRoundTrip(true, "boolean");
}

function testRefusesFunction() {
  expectThrows("refuses function ref",
    function () { assertJsonRoundTrip({ k: 1, fn: function () {} }, "row"); },
    "function ref");
}

function testRefusesBuffer() {
  expectThrows("refuses Buffer",
    function () { assertJsonRoundTrip({ data: Buffer.from("hi") }, "row"); },
    "Buffer");
}

function testRefusesDate() {
  expectThrows("refuses Date (needs pre-stringify)",
    function () { assertJsonRoundTrip({ at: new Date() }, "row"); },
    "Date");
}

function testRefusesBigInt() {
  expectThrows("refuses BigInt",
    function () { assertJsonRoundTrip({ n: 1n }, "row"); },
    "BigInt");
}

function testRefusesSymbol() {
  expectThrows("refuses Symbol",
    function () { assertJsonRoundTrip({ s: Symbol("x") }, "row"); },
    "Symbol");
}

function testRefusesUndefined() {
  expectThrows("refuses undefined field",
    function () { assertJsonRoundTrip({ k: 1, missing: undefined }, "row"); },
    "undefined");
}

function testRefusesCycle() {
  expectThrows("refuses cycle",
    function () {
      var a = { x: 1 };
      a.self = a;
      assertJsonRoundTrip(a, "row");
    },
    "cycle");
}

function testRefusesNonFiniteNumber() {
  expectThrows("refuses Infinity",
    function () { assertJsonRoundTrip({ n: Infinity }, "row"); },
    "non-finite number");
  expectThrows("refuses NaN",
    function () { assertJsonRoundTrip({ n: NaN }, "row"); },
    "non-finite number");
}

function testPathRendering() {
  // Error message should point at the offending path so operator
  // knows which field to fix.
  var threw = null;
  try {
    assertJsonRoundTrip({ outer: { inner: [1, 2, { bad: function () {} }] } }, "row");
  } catch (e) { threw = e; }
  check("path renders correctly",
    threw && threw.message.indexOf("$.outer.inner[2].bad") !== -1);
}

async function run() {
  testHappyPath();
  testRefusesFunction();
  testRefusesBuffer();
  testRefusesDate();
  testRefusesBigInt();
  testRefusesSymbol();
  testRefusesUndefined();
  testRefusesCycle();
  testRefusesNonFiniteNumber();
  testPathRendering();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
