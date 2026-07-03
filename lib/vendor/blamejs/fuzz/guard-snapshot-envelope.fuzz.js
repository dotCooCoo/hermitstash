// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: b.guardSnapshotEnvelope.validate
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var text;
  try { text = data.toString("utf8"); }
  catch (_e) { return; }
  var env;
  try { env = JSON.parse(text); } catch (_e) { return; }
  try {
    b.guardSnapshotEnvelope.validate(env);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("snapshot-envelope/") === 0) return;
    throw e;
  }
};
