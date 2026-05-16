"use strict";
/**
 * Fuzz target: b.guardMessageId.validate
 *
 * libFuzzer / jazzer.js harness — same shape as fuzz/safe-mime.fuzz.js
 * and fuzz/guard-email.fuzz.js. Targets the Message-Id header-
 * injection class (RFC 5322 §3.6.4) — CRLF / NUL / control-char
 * smuggling, RTLO bidi (CVE-2021-42574 class in mail-header context),
 * oversize chains, nested brackets.
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var input;
  try { input = data.toString("utf8"); }
  catch (_e) { return; }
  try {
    b.guardMessageId.validate(input);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("message-id/") === 0) return;
    throw e;
  }
};
