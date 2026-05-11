"use strict";
/**
 * Fuzz target: b.safeJson.parse
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (local PRs) and
 * OSS-Fuzz (continuous, Google-hosted) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer
 * the engine mutates via coverage-guided fuzzing. Seeds for the
 * initial corpus live in `fuzz/safe-json_seed_corpus/`.
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  var input;
  try { input = data.toString("utf8"); }
  catch (_e) { return; }
  try {
    b.safeJson.parse(input);
  } catch (e) {
    if (expected.isExpected(e)) return;
    throw e;
  }
};
