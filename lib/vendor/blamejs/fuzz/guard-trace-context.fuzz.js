// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: b.guardTraceContext.validate
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var input;
  try { input = data.toString("utf8"); }
  catch (_e) { return; }
  // Try both shapes: object with traceparent, or raw string.
  try {
    b.guardTraceContext.validate({ traceparent: input });
  } catch (e) {
    if (!expected.isExpected(e) && (!e || typeof e.code !== "string" ||
        e.code.indexOf("trace-context/") !== 0)) throw e;
  }
  try {
    var parsed = JSON.parse(input);
    b.guardTraceContext.validate(parsed);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("trace-context/") === 0) return;
    // SyntaxError from JSON.parse is expected for arbitrary bytes
    if (e instanceof SyntaxError) return;
    throw e;
  }
};
