"use strict";
var helpers = require("../helpers");
var b = helpers.b;
var check = helpers.check;

async function testAllPass() {
  var passed = [];
  var res = await b.bootGates.run([
    { name: "first",  fn: async function () { passed.push("first"); } },
    { name: "second", fn: async function () { passed.push("second"); } },
  ], { onPassed: function (g) {} });
  check("both gates ran",          passed.length === 2);
  check("res.passed names them",   res.passed[0] === "first" && res.passed[1] === "second");
  check("res.totalMs is finite",   isFinite(res.totalMs));
}

async function testFirstFailExits() {
  var exitedWith = null;
  var capturedFail = null;
  var ran = [];
  var res = await b.bootGates.run([
    { name: "first",  fn: async function () { ran.push("first"); } },
    { name: "fails",  fn: async function () { throw new Error("boom"); },
                      exitCode: 78, onFail: function (e) { capturedFail = e; } },
    { name: "after",  fn: async function () { ran.push("after"); } },
  ], {
    exit: function (code) { exitedWith = code; },
    log:  function () {},   // silence stderr for test
  });
  check("first ran",                    ran.indexOf("first") !== -1);
  check("after did NOT run",            ran.indexOf("after") === -1);
  check("exit called with gate code",   exitedWith === 78);
  check("onFail received error",        capturedFail !== null && capturedFail.message === "boom");
  check("res.failed names the gate",    res.failed === "fails");
}

async function testGateTimeout() {
  var exitedWith = null;
  var res = await b.bootGates.run([
    { name: "slow", timeoutMs: 50,
      fn: async function () { return new Promise(function () { /* never */ }); } },
  ], { exit: function (code) { exitedWith = code; }, log: function () {} });
  check("timeout triggers exit",        exitedWith !== null);
  check("res.failed = slow",            res.failed === "slow");
}

async function testNoExitHandlerThrows() {
  // Without opts.exit, the failure path MUST surface as a throw —
  // lib/ code never calls process.exit directly.
  var threw = false;
  try {
    await b.bootGates.run([
      { name: "fails", fn: async function () { throw new Error("boom"); } },
    ], { log: function () {} });
  } catch (e) {
    threw = true;
    check("error code is no-exit-wired", e.code === "boot-gates/no-exit-wired");
  }
  check("missing opts.exit throws", threw);
}

function testErrorClassExported() {
  check("BootGatesError exported", typeof b.bootGates.BootGatesError === "function");
}

async function testInputValidation() {
  var threw;
  threw = false; try { await b.bootGates.run([]); } catch (_e) { threw = true; }
  check("empty gates throws", threw);

  threw = false; try { await b.bootGates.run([{ name: "x" }]); } catch (_e) { threw = true; }
  check("missing fn throws", threw);
}

async function run() {
  await testAllPass();
  await testFirstFailExits();
  await testGateTimeout();
  await testNoExitHandlerThrows();
  await testInputValidation();
  testErrorClassExported();
}

if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
module.exports = { run: run };
