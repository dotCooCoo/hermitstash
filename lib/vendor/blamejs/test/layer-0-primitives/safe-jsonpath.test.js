// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeJsonPath — Postgres SQL/JSON path validator gate.
 */

var helpers = require("../helpers");
var check = helpers.check;
var b = helpers.b;
var safeJsonPath = require("../../lib/safe-jsonpath");

// Test fixtures built from char codes to keep this source file pure
// ASCII while still exercising NUL / bidi / zero-width / control
// branches.
var NUL = String.fromCharCode(0x00);
var RLO = String.fromCharCode(0x202E);   // bidi RIGHT-TO-LEFT OVERRIDE
var ZWS = String.fromCharCode(0x200B);   // zero-width space
var BEL = String.fromCharCode(0x07);     // C0 control (BEL)

function _throws(label, fn, codeRe) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check("safeJsonPath: " + label,
    threw && (codeRe ? codeRe.test(threw.code || "") || codeRe.test(threw.message || "") : true));
}

function testByteCapMultibyte() {
  // MAX_KEY_BYTES / MAX_EXPRESSION_BYTES (and opts.maxBytes) are BYTE caps.
  var mb = String.fromCharCode(0x4e2d); // one 3-byte UTF-8 char
  var t1 = null;
  try { b.safeJsonPath.validateKey(mb.repeat(5), { maxBytes: 10 }); } catch (e) { t1 = e; }
  check("safeJsonPath byte-cap: multibyte key over byte cap refused",
    t1 && t1.code === "safe-jsonpath/key-too-long");
  var t2 = null;
  try { b.safeJsonPath.validateExpression("$." + mb.repeat(5), { maxBytes: 10 }); } catch (e) { t2 = e; }
  check("safeJsonPath byte-cap: multibyte expression over byte cap refused",
    t2 && t2.code === "safe-jsonpath/expression-too-long");
}

function run() {
  testByteCapMultibyte();
  // ---- validateKey ----
  check("validateKey accepts plain key",
    safeJsonPath.validateKey("role") === "role");
  check("validateKey accepts dotted key",
    safeJsonPath.validateKey("user.id") === "user.id");

  _throws("validateKey refuses NUL",       function () { safeJsonPath.validateKey("a" + NUL + "b"); }, /control|NUL/);
  _throws("validateKey refuses bidi",      function () { safeJsonPath.validateKey("a" + RLO + "b"); }, /control|bidi|NUL/);
  _throws("validateKey refuses zero-width",function () { safeJsonPath.validateKey("a" + ZWS + "b"); }, /control|zero-width|NUL/);
  _throws("validateKey refuses C0 control",function () { safeJsonPath.validateKey("a" + BEL + "b"); }, /control|NUL/);
  _throws("validateKey refuses empty",     function () { safeJsonPath.validateKey(""); }, /non-empty/);
  _throws("validateKey refuses non-string",function () { safeJsonPath.validateKey(42); }, /string/);

  // ---- validatePointer ----
  var p = safeJsonPath.validatePointer(["users", 0, "email"]);
  check("validatePointer accepts mixed string + non-negative-int segments",
    p.length === 3 && p[0] === "users" && p[1] === 0 && p[2] === "email");

  _throws("validatePointer refuses negative int", function () { safeJsonPath.validatePointer(["a", -1]); }, /non-negative/);
  _throws("validatePointer refuses fractional int", function () { safeJsonPath.validatePointer(["a", 1.5]); }, /non-negative/);
  _throws("validatePointer refuses non-array", function () { safeJsonPath.validatePointer("nope"); }, /array/);
  _throws("validatePointer refuses bad segment", function () { safeJsonPath.validatePointer([true]); }, /string|non-negative/);

  // ---- validateExpression ----
  check("validateExpression accepts plain dotted path",
    safeJsonPath.validateExpression("$.users.email") === "$.users.email");

  _throws("validateExpression refuses filter predicate",
    function () { safeJsonPath.validateExpression("$.users[?(@.role)]"); }, /filter/);
  _throws("validateExpression refuses recursive descent",
    function () { safeJsonPath.validateExpression("$..email"); }, /deep-scan/);
  _throws("validateExpression refuses script-shape",
    function () { safeJsonPath.validateExpression("$.x(@.y.z)"); }, /script/);
  _throws("validateExpression refuses JS-source hint (semicolon)",
    function () { safeJsonPath.validateExpression("$.x;y"); }, /dynamic-hint|JS-source/);
  _throws("validateExpression refuses depth bomb",
    function () { safeJsonPath.validateExpression("$" + "[".repeat(20)); }, /too-deep|exceeds/);
  _throws("validateExpression refuses NUL",
    function () { safeJsonPath.validateExpression("$.x" + NUL + "y"); }, /control|NUL/);

  // ---- validateContainment ----
  var v = { roles: ["admin", "ops"], region: "us-east", count: 3, active: true };
  check("validateContainment accepts plain JSON shape",
    safeJsonPath.validateContainment(v) === v);

  _throws("validateContainment refuses NUL in string leaf",
    function () { safeJsonPath.validateContainment({ name: "a" + NUL + "b" }); }, /control|NUL/);

  var badKey = {};
  badKey["k" + NUL + "y"] = "value";
  _throws("validateContainment refuses NUL in object key",
    function () { safeJsonPath.validateContainment(badKey); }, /control|NUL/);

  var deep = {};
  var cur = deep;
  for (var i = 0; i < 20; i++) { cur.next = {}; cur = cur.next; }
  _throws("validateContainment refuses excessive depth",
    function () { safeJsonPath.validateContainment(deep); }, /too-deep/);

  var nested = [{ a: [1, 2, 3] }, { b: { c: "ok" } }];
  check("validateContainment accepts nested arrays",
    safeJsonPath.validateContainment(nested) === nested);

  // Surface assertions on the b.* shape so the coverage gate sees
  // direct b.safeJsonPath.* references.
  check("b.safeJsonPath.validateKey is fn",         typeof b.safeJsonPath.validateKey === "function");
  check("b.safeJsonPath.validatePointer is fn",     typeof b.safeJsonPath.validatePointer === "function");
  check("b.safeJsonPath.validateExpression is fn",  typeof b.safeJsonPath.validateExpression === "function");
  check("b.safeJsonPath.validateContainment is fn", typeof b.safeJsonPath.validateContainment === "function");
  check("b.safeJsonPath.SafeJsonPathError is fn",   typeof b.safeJsonPath.SafeJsonPathError === "function");
}

if (require.main === module) {
  try { run(); process.exit(0); }
  catch (err) { console.error(err && err.stack); process.exit(1); }
}

module.exports = { run: run };
