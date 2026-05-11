"use strict";

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var input;
  try { input = data.toString("utf8"); }
  catch (_e) { return; }
  try {
    b.safeUrl.parse(input);
  } catch (e) {
    if (expected.isExpected(e)) return;
    throw e;
  }
};
