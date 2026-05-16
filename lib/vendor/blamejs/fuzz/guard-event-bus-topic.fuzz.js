"use strict";
/**
 * Fuzz target: b.guardEventBusTopic.validate
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var input;
  try { input = data.toString("utf8"); }
  catch (_e) { return; }
  try {
    b.guardEventBusTopic.validate(input);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("event-bus-topic/") === 0) return;
    throw e;
  }
};
