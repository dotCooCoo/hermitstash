// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.safeSmtp — SMTP wire-protocol parsing helpers.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function testSurface() {
  check("findDotTerminator is fn", typeof b.safeSmtp.findDotTerminator === "function");
  check("dotUnstuff is fn",        typeof b.safeSmtp.dotUnstuff === "function");
  check("SafeSmtpError is fn",     typeof b.safeSmtp.SafeSmtpError === "function");
}

function testFindDotTerminatorCanonical() {
  var body = Buffer.from("Hello world.\r\n.\r\n", "utf8");
  var idx = b.safeSmtp.findDotTerminator(body);
  check("canonical \\r\\n.\\r\\n found at correct index",
    idx === Buffer.byteLength("Hello world.", "utf8"));
}

function testFindDotTerminatorMissing() {
  check("incomplete body returns -1",
    b.safeSmtp.findDotTerminator(Buffer.from("body without terminator")) === -1);
}

function testFindDotTerminatorStrictCrlf() {
  // Bare-LF alternate terminator MUST NOT match (smuggling defense
  // lives in b.guardSmtpCommand.detectBodySmuggling; the safe-*
  // scanner is strict-CRLF-only by construction).
  check("bare-LF \\n.\\n does not match",
    b.safeSmtp.findDotTerminator(Buffer.from("body\n.\n")) === -1);
  check("CR-only \\r.\\r does not match",
    b.safeSmtp.findDotTerminator(Buffer.from("body\r.\r")) === -1);
}

function testDotUnstuffReverses() {
  var wire = Buffer.from("hello\r\n..secret line\r\nworld\r\n", "utf8");
  var clear = b.safeSmtp.dotUnstuff(wire);
  check("'..' at line start reduced to '.'",
    clear.toString("utf8") === "hello\r\n.secret line\r\nworld\r\n");
}

function testDotUnstuffPassthrough() {
  var plain = Buffer.from("hello\r\nworld\r\n", "utf8");
  check("plain body passes through unchanged",
    b.safeSmtp.dotUnstuff(plain).toString("utf8") === "hello\r\nworld\r\n");
}

function testDotUnstuffLengthInvariant() {
  // Property: output length is always <= input length.
  var inputs = [
    Buffer.alloc(0),
    Buffer.from("hello"),
    Buffer.from("\r\n..\r\n"),
    Buffer.from("\r\n.."),
    Buffer.from("..."),
    Buffer.from("\r\n....\r\n"),
  ];
  for (var i = 0; i < inputs.length; i += 1) {
    var out = b.safeSmtp.dotUnstuff(inputs[i]);
    check("dotUnstuff output length <= input #" + i, out.length <= inputs[i].length);
  }
}

function testRefusesBadInput() {
  function expectThrow(label, fn) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("safe-smtp/") === 0);
  }
  expectThrow("findDotTerminator refuses non-Buffer",
    function () { b.safeSmtp.findDotTerminator("not-a-buffer"); });
  expectThrow("dotUnstuff refuses non-Buffer",
    function () { b.safeSmtp.dotUnstuff("not-a-buffer"); });
}

function run() {
  testSurface();
  testFindDotTerminatorCanonical();
  testFindDotTerminatorMissing();
  testFindDotTerminatorStrictCrlf();
  testDotUnstuffReverses();
  testDotUnstuffPassthrough();
  testDotUnstuffLengthInvariant();
  testRefusesBadInput();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[safe-smtp] OK"); }
  catch (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); }
}
