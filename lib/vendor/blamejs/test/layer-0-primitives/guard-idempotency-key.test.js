// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function expectRefused(label, fn, codeMatch) {
  var threw = null;
  try { fn(); } catch (e) { threw = e; }
  check(label, threw && (threw.code || "").indexOf(codeMatch) !== -1);
}

function testSurface() {
  check("validate fn",          typeof b.guardIdempotencyKey.validate === "function");
  check("compliancePosture fn", typeof b.guardIdempotencyKey.compliancePosture === "function");
  check("NAME = idempotencyKey", b.guardIdempotencyKey.NAME === "idempotencyKey");
  check("KIND = idempotency-key", b.guardIdempotencyKey.KIND === "idempotency-key");
  check("PROFILES frozen",      Object.isFrozen(b.guardIdempotencyKey.PROFILES));
  check("GuardIdempotencyKeyError is fn",
    typeof b.guardIdempotencyKey.GuardIdempotencyKeyError === "function");
  var e = new b.guardIdempotencyKey.GuardIdempotencyKeyError("idempotency-key/test", "t");
  check("error carries code",   e.code === "idempotency-key/test");
  check("compliancePosture hipaa",
    b.guardIdempotencyKey.compliancePosture("hipaa") === "strict");
  check("compliancePosture unknown",
    b.guardIdempotencyKey.compliancePosture("nope") === null);
}

function testValid() {
  b.guardIdempotencyKey.validate("jmap-req-abc-123");
  b.guardIdempotencyKey.validate("uuid-v4-style-deadbeef-cafe-1234-5678-9abcdef01234");
  b.guardIdempotencyKey.validate("operator.event.send_message:2026-05-14T18:30Z:tenant-acme:msg-42");
}

function testRefuses() {
  expectRefused("refuses non-string",
    function () { b.guardIdempotencyKey.validate(42); },
    "idempotency-key/bad-input");
  expectRefused("refuses empty",
    function () { b.guardIdempotencyKey.validate(""); },
    "idempotency-key/empty");
  expectRefused("refuses CR (audit-log injection class)",
    function () { b.guardIdempotencyKey.validate("a\rb"); },
    "idempotency-key/control-char");
  expectRefused("refuses LF",
    function () { b.guardIdempotencyKey.validate("a\nb"); },
    "idempotency-key/control-char");
  expectRefused("refuses NUL",
    function () { b.guardIdempotencyKey.validate("a\x00b"); },
    "idempotency-key/control-char");
  expectRefused("refuses slash",
    function () { b.guardIdempotencyKey.validate("a/b"); },
    "idempotency-key/slash");
  expectRefused("refuses backslash",
    function () { b.guardIdempotencyKey.validate("a\\b"); },
    "idempotency-key/slash");
  expectRefused("refuses path-traversal",
    function () { b.guardIdempotencyKey.validate("x..y"); },
    "idempotency-key/path-traversal");
  expectRefused("refuses non-ascii under strict",
    function () { b.guardIdempotencyKey.validate("clé-français"); },
    "idempotency-key/non-ascii");
  expectRefused("refuses oversize",
    function () {
      var big = "k";
      for (var i = 0; i < 9; i += 1) big += big;        // 512 chars
      b.guardIdempotencyKey.validate(big);
    },
    "idempotency-key/oversize");
}

function testPermissive() {
  // Permissive opts down the non-ASCII refusal (operator with Unicode tenant IDs).
  b.guardIdempotencyKey.validate("clé-français", { profile: "permissive" });
  // But control chars still refused at every profile.
  expectRefused("permissive still refuses control char",
    function () { b.guardIdempotencyKey.validate("a\rb", { profile: "permissive" }); },
    "idempotency-key/control-char");
}

async function run() {
  testSurface();
  testValid();
  testRefuses();
  testPermissive();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
