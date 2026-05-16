"use strict";
/**
 * Fuzz target: b.guardMailQuery.validate
 *
 * libFuzzer / jazzer.js harness. Targets the search/fetch filter
 * structural-validation surface: function smuggling, regex smuggling,
 * cycle detection, depth/key/array caps, projection-column allowlist,
 * scalar refusal (BigInt / Symbol / undefined).
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var text;
  try { text = data.toString("utf8"); }
  catch (_e) { return; }
  var filter;
  try { filter = JSON.parse(text); } catch (_e) { return; }
  try {
    b.guardMailQuery.validate(filter);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("mail-query/") === 0) return;
    throw e;
  }
};
