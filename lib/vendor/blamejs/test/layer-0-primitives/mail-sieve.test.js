// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("b.mail.sieve.run exists",       typeof b.mail.sieve.run === "function");
  check("b.mail.sieve.runScript exists", typeof b.mail.sieve.runScript === "function");
  check("b.mail.sieve.create exists",    typeof b.mail.sieve.create === "function");
}

function testImplicitKeep() {
  var rv = b.mail.sieve.runScript('# empty script\r\n', {});
  check("implicit keep when no action fires",
    rv.actions.length === 1 && rv.actions[0].kind === "keep" && rv.actions[0].implicit);
}

function testFileinto() {
  var script = 'require ["fileinto"];\r\n' +
    'if header :contains "Subject" "[bug]" { fileinto "bugs"; }\r\n';
  var rv = b.mail.sieve.runScript(script, {
    headers: [{ name: "Subject", value: "Re: [bug] crash" }],
  });
  check("fileinto fires + cancels implicit keep",
    rv.actions.length === 1 && rv.actions[0].kind === "fileinto" && rv.actions[0].folder === "bugs");
}

function testAddressDomain() {
  var script = 'if address :is :domain "From" "trusted.com" { keep; }\r\n';
  var rv1 = b.mail.sieve.runScript(script, {
    headers: [{ name: "From", value: "alice@trusted.com" }],
  });
  check("address :domain match",
    rv1.actions.length === 1 && rv1.actions[0].kind === "keep");
  var rv2 = b.mail.sieve.runScript(script, {
    headers: [{ name: "From", value: "alice@untrusted.com" }],
  });
  check("address :domain non-match → implicit keep",
    rv2.actions[0].implicit === true);
}

function testEnvelope() {
  var script = 'if envelope :is "from" "boss@example.com" { fileinto "Boss"; }\r\n';
  var rv = b.mail.sieve.runScript(script, {
    envelope: { from: "boss@example.com", to: "me@example.com" },
    headers:  [],
  });
  check("envelope test reads env.envelope",
    rv.actions[0].kind === "fileinto" && rv.actions[0].folder === "Boss");
}

function testSize() {
  var script = 'if size :over 1K { discard; }\r\n';
  var big = b.mail.sieve.runScript(script, { sizeBytes: 2048 });
  check("size :over fires on 2KB",
    big.actions[0].kind === "discard");
  var small = b.mail.sieve.runScript(script, { sizeBytes: 512 });
  check("size :over below threshold → implicit keep",
    small.actions[0].implicit === true);
}

function testWildcardMatches() {
  var script = 'if header :matches "Subject" "[bug]*" { fileinto "bugs"; }\r\n';
  var rv = b.mail.sieve.runScript('require ["fileinto"];\r\n' + script, {
    headers: [{ name: "Subject", value: "[bug] tracker #42" }],
  });
  check("`:matches` wildcard fires",
    rv.actions[0].kind === "fileinto");
}

function testAnyofAllof() {
  var script =
    'if anyof(header :is "X-Spam" "yes", header :contains "Subject" "viagra") {\r\n' +
    '  discard;\r\n' +
    '}\r\n';
  var rv = b.mail.sieve.runScript(script, {
    headers: [{ name: "Subject", value: "buy viagra now" }],
  });
  check("anyof matches second branch", rv.actions[0].kind === "discard");
}

function testRedirect() {
  var script = 'if header :is "From" "alerts@example.com" { redirect "ops@example.com"; }\r\n';
  var rv = b.mail.sieve.runScript(script, {
    headers: [{ name: "From", value: "alerts@example.com" }],
  });
  check("redirect captures address",
    rv.actions[0].kind === "redirect" && rv.actions[0].address === "ops@example.com");
}

function testStop() {
  var script =
    'if header :is "From" "ignore@x.com" { stop; }\r\n' +
    'keep;\r\n';
  var rv = b.mail.sieve.runScript(script, {
    headers: [{ name: "From", value: "ignore@x.com" }],
  });
  check("stop halts further commands → implicit keep applies (no explicit keep ran)",
    rv.stopped === true);
}

function testGasExhaustion() {
  // Wide allof to consume gas without nesting.
  var subs = []; for (var i = 0; i < 20; i++) subs.push("true");
  var script = "if allof(" + subs.join(", ") + ") { keep; }\r\n";
  var threw = null;
  try { b.mail.sieve.runScript(script, {}, { maxGas: 3 }); } catch (e) { threw = e; }
  check("gas exhaustion throws",
    threw && threw.code === "mail-sieve/gas-exhausted");
}

function testBadAst() {
  var threw = null;
  try { b.mail.sieve.run({ notAnAst: true }, {}); } catch (e) { threw = e; }
  check("non-script ast refused",
    threw && threw.code === "mail-sieve/bad-ast");
}

function testCreateHandle() {
  var sieve = b.mail.sieve.create({ maxGas: 100 });
  var rv = sieve.runScript('require ["fileinto"];\r\nfileinto "Test";\r\n', { headers: [] });
  check("handle runScript returns action",
    rv.actions[0].kind === "fileinto" && rv.actions[0].folder === "Test");
  var v = sieve.validateScript('require ["nonsense"];\nkeep;\n');
  check("handle validateScript surfaces unknown cap",
    !v.ok && v.issues[0].ruleId === "safe-sieve/unknown-capability");
}

function run() {
  testSurface();
  testImplicitKeep();
  testFileinto();
  testAddressDomain();
  testEnvelope();
  testSize();
  testWildcardMatches();
  testAnyofAllof();
  testRedirect();
  testStop();
  testGasExhaustion();
  testBadAst();
  testCreateHandle();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[mail-sieve] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
