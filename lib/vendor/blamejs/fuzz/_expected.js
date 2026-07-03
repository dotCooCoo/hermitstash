// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Shared "is this throw expected?" classifier used by every jazzer.js
 * fuzz harness in this directory.
 *
 * Framework convention: every operator-friendly throw carries
 * `err.code` of shape `<domain><sep><error-name>` where sep is `/`
 * (most modules: `safe-url/malformed`, `json/syntax`) or `.` (guard
 * family: `json.null-byte`, `guard-yaml.refused`). The fuzz harness
 * accepts any such code, plus node-builtin error subclasses with
 * input-shape messaging — operator-supplied bytes legitimately
 * triggered a documented refusal path.
 *
 * Anything else is a finding: the fuzz target either crashed on
 * adversarial input or surfaced an unguarded internal invariant
 * break. libFuzzer (under ClusterFuzzLite / OSS-Fuzz) records the
 * reproducer + persists it in the corpus so future runs catch
 * regressions.
 */

var FRAMEWORK_CODE_RE = /^[a-z][a-z0-9-]*[/.][a-z]/;
var INPUT_SHAPE_RE    = /must be|expected|invalid|bad|unsupported|unknown|missing/i;
var CAP_RE            = /too|max|exceed|limit|cap/i;

function isExpected(e) {
  if (!e) return false;
  if (typeof e.code === "string" && FRAMEWORK_CODE_RE.test(e.code)) return true;
  if (e instanceof TypeError && INPUT_SHAPE_RE.test(e.message || "")) return true;
  if (e instanceof SyntaxError) return true;
  if (e instanceof URIError) return true;
  if (e instanceof RangeError && CAP_RE.test(e.message || "")) return true;
  return false;
}

module.exports = { isExpected: isExpected };
