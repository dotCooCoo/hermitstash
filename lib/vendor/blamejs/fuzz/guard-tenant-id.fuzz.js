"use strict";
/**
 * Fuzz target: b.guardTenantId.validate
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var input;
  try { input = data.toString("utf8"); }
  catch (_e) { return; }
  try {
    b.guardTenantId.validate(input);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("tenant-id/") === 0) return;
    throw e;
  }
};
