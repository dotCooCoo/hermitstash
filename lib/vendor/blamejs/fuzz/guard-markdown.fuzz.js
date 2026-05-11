"use strict";

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var input;
  try { input = data.toString("utf8"); }
  catch (_e) { return; }
  try {
    b.guardMarkdown.validate(input, { profile: "strict" });
  } catch (e) {
    if (expected.isExpected(e)) return;
    throw e;
  }
};
