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
  check("validate fn",     typeof b.guardMailMove.validate === "function");
  check("NAME = mailMove", b.guardMailMove.NAME === "mailMove");
  check("KIND = mail-move", b.guardMailMove.KIND === "mail-move");
  check("SYSTEM_FOLDERS frozen", Object.isFrozen(b.guardMailMove.SYSTEM_FOLDERS));
  check("GuardMailMoveError is fn", typeof b.guardMailMove.GuardMailMoveError === "function");
  var e = new b.guardMailMove.GuardMailMoveError("mail-move/test", "test");
  check("GuardMailMoveError instances carry code", e.code === "mail-move/test");
  check("compliancePosture hipaa", b.guardMailMove.compliancePosture("hipaa") === "strict");
  check("compliancePosture unknown", b.guardMailMove.compliancePosture("nope") === null);
}

function testValid() {
  b.guardMailMove.validate({
    actor:      { id: "u1" },
    fromFolder: "INBOX",
    toFolder:   "Archive",
    objectIds:  ["abc123"],
  });
}

function testRefuses() {
  expectRefused("refuses missing actor",
    function () { b.guardMailMove.validate({ fromFolder: "INBOX", toFolder: "Trash", objectIds: ["x"] }); },
    "mail-move/no-actor");
  expectRefused("refuses same folder",
    function () {
      b.guardMailMove.validate({
        actor: { id: "u1" }, fromFolder: "INBOX", toFolder: "INBOX", objectIds: ["x"],
      });
    },
    "mail-move/same-folder");
  expectRefused("refuses path traversal",
    function () {
      b.guardMailMove.validate({
        actor: { id: "u1" }, fromFolder: "INBOX", toFolder: "../etc", objectIds: ["x"],
      });
    },
    "mail-move/path-traversal");
  expectRefused("refuses slash in name",
    function () {
      b.guardMailMove.validate({
        actor: { id: "u1" }, fromFolder: "INBOX", toFolder: "Projects/Work", objectIds: ["x"],
      });
    },
    "mail-move/slash-in-name");
  expectRefused("refuses hidden folder",
    function () {
      b.guardMailMove.validate({
        actor: { id: "u1" }, fromFolder: "INBOX", toFolder: ".hidden", objectIds: ["x"],
      });
    },
    "mail-move/hidden-name");
  expectRefused("refuses control char",
    function () {
      b.guardMailMove.validate({
        actor: { id: "u1" }, fromFolder: "INBOX", toFolder: "Bad\rFolder", objectIds: ["x"],
      });
    },
    "mail-move/control-char-in-name");
  expectRefused("refuses non-system custom folder without admin / allowedFolders",
    function () {
      b.guardMailMove.validate({
        actor: { id: "u1" }, fromFolder: "INBOX", toFolder: "Projects", objectIds: ["x"],
      });
    },
    "mail-move/destination-not-allowed");
  expectRefused("refuses empty objectIds",
    function () {
      b.guardMailMove.validate({
        actor: { id: "u1" }, fromFolder: "INBOX", toFolder: "Trash", objectIds: [],
      });
    },
    "mail-move/empty-objectids");
}

function testScopes() {
  b.guardMailMove.validate({
    actor: { id: "u1", mailScope: "admin" }, fromFolder: "INBOX", toFolder: "Projects", objectIds: ["x"],
  });
  b.guardMailMove.validate({
    actor: { id: "u1", allowedFolders: ["Projects", "Bills"] },
    fromFolder: "INBOX", toFolder: "Bills", objectIds: ["x"],
  });
}

async function run() {
  testSurface();
  testValid();
  testRefuses();
  testScopes();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
