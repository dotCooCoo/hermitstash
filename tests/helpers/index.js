"use strict";
/**
 * tests/helpers — shim layer so the vendored lint tests
 * (codebase-patterns.test.js, test-coverage.test.js) compile against
 * the same shape they had in the blamejs repo. Re-exports the named
 * helpers each vendored test imports:
 *
 *   var { check, b } = require("../helpers");
 */

var _check = require("./check");
var b      = require("../../lib/vendor/blamejs");

module.exports = {
  check:               _check.check,
  getChecks:           _check.getChecks,
  resetChecksForTest:  _check.resetChecksForTest,
  addExternalChecks:   _check.addExternalChecks,
  b:                   b,
};
