// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Fuzz target: b.safeMime.parse
 *
 * libFuzzer / jazzer.js harness. ClusterFuzzLite (local PRs) and
 * OSS-Fuzz (continuous, Google-hosted) both consume this shape:
 * `module.exports.fuzz = function (data)` where `data` is a Buffer
 * the engine mutates via coverage-guided fuzzing. Seeds for the
 * initial corpus live in `fuzz/safe-mime_seed_corpus/`.
 *
 * Targets the MIME-parser-bypass class: CVE-2024-39929 (Exim multipart),
 * CVE-2025-30258 (gnumail truncated tree), plus boundary/charset/CTE
 * smuggling shapes.
 */

var b        = require("..");
var expected = require("./_expected");

module.exports.fuzz = function (data) {
  try {
    b.safeMime.parse(data);
  } catch (e) {
    if (expected.isExpected(e)) return;
    if (e && typeof e.code === "string" && e.code.indexOf("safe-mime/") === 0) return;
    throw e;
  }
};
