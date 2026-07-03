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
  check("validate fn",       typeof b.guardMailSieve.validate === "function");
  check("NAME = mailSieve",  b.guardMailSieve.NAME === "mailSieve");
  check("KIND = mail-sieve", b.guardMailSieve.KIND === "mail-sieve");
  check("GuardMailSieveError is fn", typeof b.guardMailSieve.GuardMailSieveError === "function");
  var e = new b.guardMailSieve.GuardMailSieveError("mail-sieve/test", "test");
  check("GuardMailSieveError instances carry code", e.code === "mail-sieve/test");
  check("compliancePosture hipaa", b.guardMailSieve.compliancePosture("hipaa") === "strict");
  check("compliancePosture unknown", b.guardMailSieve.compliancePosture("nope") === null);
}

function testValidPut() {
  b.guardMailSieve.validate({
    kind:   "put",
    actor:  { id: "u1" },
    name:   "my-filter",
    script: "require [\"fileinto\"];\nif address :is \"From\" \"x@x\" { fileinto \"Junk\"; }",
  }, { ownedNames: ["my-filter"] });
}

function testRefuses() {
  expectRefused("refuses bad kind",
    function () { b.guardMailSieve.validate({ kind: "weird", actor: { id: "u1" }, name: "x" }); },
    "mail-sieve/bad-kind");
  expectRefused("refuses bad name (path traversal)",
    function () {
      b.guardMailSieve.validate({ kind: "put", actor: { id: "u1" }, name: "../etc/passwd", script: "stop;" },
                                { ownedNames: ["../etc/passwd"] });
    },
    "mail-sieve/path-traversal");
  expectRefused("refuses bad name char (slash)",
    function () {
      b.guardMailSieve.validate({ kind: "put", actor: { id: "u1" }, name: "a/b", script: "stop;" },
                                { ownedNames: ["a/b"] });
    },
    "mail-sieve/bad-name-char");
  expectRefused("refuses empty script",
    function () {
      b.guardMailSieve.validate({ kind: "put", actor: { id: "u1" }, name: "x", script: "" },
                                { ownedNames: ["x"] });
    },
    "mail-sieve/empty-script");
  expectRefused("refuses control char in script",
    function () {
      b.guardMailSieve.validate({ kind: "put", actor: { id: "u1" }, name: "x", script: "stop\x00;" },
                                { ownedNames: ["x"] });
    },
    "mail-sieve/control-char-in-script");
  expectRefused("refuses not-owner",
    function () {
      b.guardMailSieve.validate({ kind: "put", actor: { id: "u1" }, name: "someone-elses", script: "stop;" },
                                { ownedNames: ["mine-only"] });
    },
    "mail-sieve/not-owner");
}

function testScopes() {
  // Admin can edit any script.
  b.guardMailSieve.validate({
    kind: "put", actor: { id: "admin1", mailScope: "admin" },
    name: "another-users-script", script: "stop;",
  });
  // Activate / delete don't need a script.
  b.guardMailSieve.validate({
    kind: "activate", actor: { id: "u1" }, name: "my-filter",
  }, { ownedNames: ["my-filter"] });
}

async function run() {
  testSurface();
  testValidPut();
  testRefuses();
  testScopes();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
