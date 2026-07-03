// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var b        = require("..");
var expected = require("./_expected");

// Fuzz the free-text guard's two parsing surfaces: validate() (pure inspection,
// must never throw on arbitrary bytes) and sanitize() (strip pass, must either
// return a shrunk string or throw a recognized GuardTextError, never crash).
module.exports.fuzz = function (data) {
  var input;
  try { input = data.toString("utf8"); }
  catch (_e) { return; }
  try {
    b.guardText.validate(input, { profile: "strict" });
    b.guardText.sanitize(input, { profile: "balanced" });
  } catch (e) {
    if (expected.isExpected(e)) return;
    throw e;
  }
};
