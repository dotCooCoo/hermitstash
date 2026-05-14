"use strict";
/**
 * check + counter shim — compatible with the blamejs test-helper API so
 * codebase-patterns.test.js and test-coverage.test.js (vendored from the
 * framework) run as-is against HermitStash's lib/ and tests/.
 *
 * `check(label, condition)` throws on failure (the node:test wrapper
 * surfaces it as a test failure) and increments a process-wide counter.
 * `getChecks()` reports the running total for human-readable summaries.
 */

var _checks = 0;

function check(label, condition) {
  if (!condition) throw new Error("FAIL: " + label);
  _checks += 1;
}

function getChecks() { return _checks; }
function resetChecksForTest() { _checks = 0; }
function addExternalChecks(n) {
  if (typeof n === "number" && isFinite(n) && n >= 0) _checks += n;
}

module.exports = {
  check: check,
  getChecks: getChecks,
  resetChecksForTest: resetChecksForTest,
  addExternalChecks: addExternalChecks,
};
