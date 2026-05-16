"use strict";
/**
 * Fuzz target: b.guardIdempotencyKey.validate
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var input;
  try { input = data.toString("utf8"); }
  catch (_e) { return; }
  try {
    b.guardIdempotencyKey.validate(input);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("idempotency-key/") === 0) return;
    throw e;
  }
};
