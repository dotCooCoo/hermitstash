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
  check("validate fn",          typeof b.guardStreamArgs.validate === "function");
  check("compliancePosture fn", typeof b.guardStreamArgs.compliancePosture === "function");
  check("NAME = streamArgs",    b.guardStreamArgs.NAME === "streamArgs");
  check("KIND = stream-args",   b.guardStreamArgs.KIND === "stream-args");
  check("PROFILES frozen",      Object.isFrozen(b.guardStreamArgs.PROFILES));
  check("GuardStreamArgsError is fn",
    typeof b.guardStreamArgs.GuardStreamArgsError === "function");
  var e = new b.guardStreamArgs.GuardStreamArgsError("stream-args/test", "t");
  check("error carries code",   e.code === "stream-args/test");
  check("compliancePosture hipaa",   b.guardStreamArgs.compliancePosture("hipaa") === "strict");
  check("compliancePosture unknown", b.guardStreamArgs.compliancePosture("nope") === null);
}

function testValid() {
  b.guardStreamArgs.validate({ batchSize: 256, kind: "search" });
  b.guardStreamArgs.validate({ batchSize: 1024, kind: "export", cursorOpts: { folder: "INBOX" } });
  b.guardStreamArgs.validate({});                                          // all opts optional
}

function testRefuses() {
  expectRefused("refuses bad input",
    function () { b.guardStreamArgs.validate(null); },
    "stream-args/bad-input");
  expectRefused("refuses fractional batchSize",
    function () { b.guardStreamArgs.validate({ batchSize: 1.5 }); },
    "stream-args/bad-batch-size");
  expectRefused("refuses batchSize 0",
    function () { b.guardStreamArgs.validate({ batchSize: 0 }); },
    "stream-args/batch-size-out-of-range");
  expectRefused("refuses batchSize over cap",
    function () { b.guardStreamArgs.validate({ batchSize: 1000000 }); },
    "stream-args/batch-size-out-of-range");
  expectRefused("refuses empty kind",
    function () { b.guardStreamArgs.validate({ kind: "" }); },
    "stream-args/bad-kind");
  expectRefused("refuses function in cursorOpts",
    function () { b.guardStreamArgs.validate({ cursorOpts: { pred: function () {} } }); },
    "stream-args/function-not-allowed");
  expectRefused("refuses regex in cursorOpts",
    function () { b.guardStreamArgs.validate({ cursorOpts: { subject: /x/ } }); },
    "stream-args/regex-not-allowed");
  expectRefused("refuses Buffer in cursorOpts",
    function () { b.guardStreamArgs.validate({ cursorOpts: { data: Buffer.from("x") } }); },
    "stream-args/buffer-not-allowed");
  expectRefused("refuses cursorOpts too deep",
    function () {
      var deep = {};
      var cur  = deep;
      for (var i = 0; i < 10; i += 1) { cur.nested = {}; cur = cur.nested; }
      b.guardStreamArgs.validate({ cursorOpts: deep });
    },
    "stream-args/cursor-opts-too-deep");
}

async function run() {
  testSurface();
  testValid();
  testRefuses();
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
