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
  check("validate fn",          typeof b.guardSagaConfig.validate === "function");
  check("compliancePosture fn", typeof b.guardSagaConfig.compliancePosture === "function");
  check("NAME = sagaConfig",    b.guardSagaConfig.NAME === "sagaConfig");
  check("KIND = saga-config",   b.guardSagaConfig.KIND === "saga-config");
  check("PROFILES frozen",      Object.isFrozen(b.guardSagaConfig.PROFILES));
  var e = new b.guardSagaConfig.GuardSagaConfigError("saga-config/test", "t");
  check("error carries code",   e.code === "saga-config/test");
  check("compliancePosture hipaa", b.guardSagaConfig.compliancePosture("hipaa") === "strict");
  check("compliancePosture unknown", b.guardSagaConfig.compliancePosture("nope") === null);
}

function testValid() {
  b.guardSagaConfig.validate({
    name: "mail.send",
    steps: [
      { name: "sign", run: async function () {}, compensate: async function () {} },
      { name: "deliver", run: async function () {} },
    ],
  });
}

function testRefuses() {
  expectRefused("refuses missing name",
    function () { b.guardSagaConfig.validate({ steps: [{ name: "x", run: async function () {} }] }); },
    "saga-config/bad-name");
  expectRefused("refuses empty steps",
    function () { b.guardSagaConfig.validate({ name: "x", steps: [] }); },
    "saga-config/no-steps");
  expectRefused("refuses duplicate step names",
    function () {
      b.guardSagaConfig.validate({
        name: "x",
        steps: [
          { name: "step", run: async function () {} },
          { name: "step", run: async function () {} },
        ],
      });
    }, "saga-config/duplicate-step-name");
  expectRefused("refuses non-function run",
    function () {
      b.guardSagaConfig.validate({ name: "x", steps: [{ name: "s", run: "not-a-fn" }] });
    }, "saga-config/bad-step-run");
  expectRefused("refuses non-function compensate",
    function () {
      b.guardSagaConfig.validate({
        name: "x",
        steps: [{ name: "s", run: async function () {}, compensate: "not-a-fn" }],
      });
    }, "saga-config/bad-step-compensate");
  expectRefused("refuses non-ASCII name",
    function () {
      b.guardSagaConfig.validate({ name: "café-saga", steps: [{ name: "s", run: async function () {} }] });
    }, "saga-config/non-ascii-name");
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
