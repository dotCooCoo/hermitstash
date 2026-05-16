"use strict";
/**
 * Fuzz target: b.guardMailMove.validate
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var text;
  try { text = data.toString("utf8"); }
  catch (_e) { return; }
  var move;
  try { move = JSON.parse(text); } catch (_e) { return; }
  try {
    b.guardMailMove.validate(move);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("mail-move/") === 0) return;
    throw e;
  }
};
