"use strict";
/**
 * Fuzz target: b.guardAgentRegistry.validate
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var text;
  try { text = data.toString("utf8"); }
  catch (_e) { return; }
  var op;
  try { op = JSON.parse(text); } catch (_e) { return; }
  try {
    b.guardAgentRegistry.validate(op);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("agent-registry/") === 0) return;
    throw e;
  }
};
