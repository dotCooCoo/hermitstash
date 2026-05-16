"use strict";
/**
 * Fuzz target: b.guardEventBusPayload.validate
 */

var b        = require("..");
var expected = require("./_expected");

var FIXED_SCHEMA = { source: "string", confidence: "number", "reason?": "string" };

module.exports.fuzz = function (data) {
  var text;
  try { text = data.toString("utf8"); }
  catch (_e) { return; }
  var payload;
  try { payload = JSON.parse(text); } catch (_e) { return; }
  try {
    b.guardEventBusPayload.validate(payload, FIXED_SCHEMA);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("event-bus-payload/") === 0) return;
    throw e;
  }
};
