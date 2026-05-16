"use strict";
/**
 * Fuzz target: b.guardSagaConfig.validate
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var text;
  try { text = data.toString("utf8"); }
  catch (_e) { return; }
  var cfg;
  try { cfg = JSON.parse(text); } catch (_e) { return; }
  // JSON.parse can't deliver functions; substitute a placeholder so the
  // type checks fire against operator-supplied non-function inputs.
  if (cfg && Array.isArray(cfg.steps)) {
    for (var i = 0; i < cfg.steps.length; i += 1) {
      var s = cfg.steps[i];
      if (s && typeof s === "object" && typeof s.run === "string") {
        // leave as string to exercise the validator's type cascade
      }
    }
  }
  try {
    b.guardSagaConfig.validate(cfg);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("saga-config/") === 0) return;
    throw e;
  }
};
