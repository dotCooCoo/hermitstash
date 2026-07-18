// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.log.makeViaOrFallback — operator-log routing closure that falls
 * back to a per-module logger when the operator didn't pass one.
 *
 * Run standalone: `node test/layer-0-primitives/log.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

// A recording fallback logger with the boot()-shape surface
// (info/warn/error take a single pre-formatted line).
function _recordingFallback() {
  var lines = [];
  return {
    lines: lines,
    info:  function (line) { lines.push(["info",  line]); },
    warn:  function (line) { lines.push(["warn",  line]); },
    error: function (line) { lines.push(["error", line]); },
  };
}

function testFallbackFiresWhenOperatorLogAbsent() {
  var fb = _recordingFallback();
  var via = b.log.makeViaOrFallback(null, fb);
  via("error", "build-failed", { reason: "missing entrypoint" });
  check("makeViaOrFallback: routes to fallback.error with a formatted line",
        fb.lines.length === 1 &&
        fb.lines[0][0] === "error" &&
        fb.lines[0][1] === 'build-failed {"reason":"missing entrypoint"}');
}

function testFallbackLevelMapping() {
  var fb = _recordingFallback();
  var via = b.log.makeViaOrFallback(null, fb);
  via("warn", "warned");                 // → fallback.warn
  via("info", "informed");               // → fallback.info
  via("fatal", "fatal-line");            // fatal + error both route to fallback.error
  check("makeViaOrFallback: warn → fallback.warn", fb.lines[0][0] === "warn" && fb.lines[0][1] === "warned");
  check("makeViaOrFallback: info → fallback.info", fb.lines[1][0] === "info" && fb.lines[1][1] === "informed");
  check("makeViaOrFallback: fatal maps to fallback.error", fb.lines[2][0] === "error" && fb.lines[2][1] === "fatal-line");
}

function testOperatorLogWinsWhenLevelPresent() {
  var fb = _recordingFallback();
  var opCalls = [];
  var operatorLog = { error: function (message, fields) { opCalls.push([message, fields]); } };
  var via = b.log.makeViaOrFallback(operatorLog, fb);
  via("error", "op-msg", { a: 1 });
  check("makeViaOrFallback: operator log receives (message, fields) verbatim",
        opCalls.length === 1 && opCalls[0][0] === "op-msg" && opCalls[0][1].a === 1);
  check("makeViaOrFallback: fallback NOT called when operator handles the level",
        fb.lines.length === 0);
}

function testFallbackFiresWhenOperatorMissingLevel() {
  var fb = _recordingFallback();
  // Operator log exposes only info(); an error() call must fall back.
  var operatorLog = { info: function () {} };
  var via = b.log.makeViaOrFallback(operatorLog, fb);
  via("error", "no-operator-error-method");
  check("makeViaOrFallback: falls back when operator lacks the requested level",
        fb.lines.length === 1 && fb.lines[0][0] === "error" &&
        fb.lines[0][1] === "no-operator-error-method");
}

function testOperatorLogThrowIsSwallowed() {
  var fb = _recordingFallback();
  var operatorLog = { error: function () { throw new Error("operator log blew up"); } };
  var via = b.log.makeViaOrFallback(operatorLog, fb);
  var threw = null;
  try { via("error", "boom"); } catch (e) { threw = e; }
  check("makeViaOrFallback: a throwing operator log is swallowed (best-effort)", threw === null);
  check("makeViaOrFallback: no fallback double-emit after operator log threw", fb.lines.length === 0);
}

function testMessageWithoutFieldsFormatsBareLine() {
  var fb = _recordingFallback();
  var via = b.log.makeViaOrFallback(null, fb);
  via("info", "no-fields-here");   // no fields arg → line is the message verbatim
  check("makeViaOrFallback: a fields-less call formats the bare message",
        fb.lines.length === 1 && fb.lines[0][1] === "no-fields-here");
}

async function run() {
  testFallbackFiresWhenOperatorLogAbsent();
  testFallbackLevelMapping();
  testOperatorLogWinsWhenLevelPresent();
  testFallbackFiresWhenOperatorMissingLevel();
  testOperatorLogThrowIsSwallowed();
  testMessageWithoutFieldsFormatsBareLine();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("log tests passed"); process.exit(0); },
    function (e) { console.error(e); process.exit(1); }
  );
}
