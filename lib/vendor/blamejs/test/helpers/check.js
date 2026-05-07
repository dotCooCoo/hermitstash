"use strict";
/**
 * check + counter — the framework's custom assertion + cross-file
 * counter (kept instead of node:test for now; the per-file split is
 * the modularity win, the assertion swap is orthogonal scope).
 *
 * One global counter shared by every test file via this module's
 * singleton-require semantics. The smoke runner reads getChecks()
 * after walking every layer to print the total.
 */

var _checks = 0;

function check(label, condition) {
  if (!condition) throw new Error("FAIL: " + label);
  _checks += 1;
}

function getChecks()         { return _checks; }
function resetChecksForTest() { _checks = 0; }

// addExternalChecks — the parallel smoke runner forks per-file
// children; each child runs its own _checks counter in its process
// and reports it back to the parent. The parent calls this to fold
// the children's counts into the parent total so the final
// "OK — N checks passed" line aggregates correctly.
function addExternalChecks(n) {
  if (typeof n === "number" && isFinite(n) && n >= 0) _checks += n;
}

module.exports = {
  check:              check,
  getChecks:          getChecks,
  resetChecksForTest: resetChecksForTest,
  addExternalChecks:  addExternalChecks,
};
