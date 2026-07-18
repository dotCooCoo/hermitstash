// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-time — RFC 3339 / ISO 8601 datetime identifier-safety primitive
 * (b.guardTime).
 *
 * Covers the inspect-vs-throw split: `validate` returns `{ ok, issues }`
 * without throwing (non-string input yields a `time.bad-input` issue),
 * while `sanitize` normalizes the string (legacy-space → `T`, trailing
 * `z` → `Z`) and throws GuardTimeError on any critical / high finding.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _code(fn) { try { fn(); return null; } catch (e) { return e && e.code; } }
function _hasKind(rv, kind) {
  return rv.issues.some(function (i) { return i.kind === kind; });
}

function testGuardTimeSurface() {
  check("guardTime is an object",           typeof b.guardTime === "object");
  check("guardTime.NAME === 'time'",        b.guardTime.NAME === "time");
  check("guardTime.validate is a function", typeof b.guardTime.validate === "function");
  check("guardTime.sanitize is a function", typeof b.guardTime.sanitize === "function");
  check("guardTime registered in guardAll",
    b.guardAll.allGuards().some(function (g) { return (g.name || g.NAME) === "time"; }));
}

function testValidateAcceptsUtcDatetime() {
  var rv = b.guardTime.validate("2026-05-05T12:34:56Z", { profile: "strict" });
  check("well-formed UTC datetime → ok:true", rv.ok === true && rv.issues.length === 0);
}

function testValidatePreEpochYearWindow() {
  // 1969 is before the Unix-epoch floor (minYear default 1970).
  var rv = b.guardTime.validate("1969-12-31T23:59:59Z", { profile: "strict" });
  check("pre-epoch year → ok:false", rv.ok === false);
  check("pre-epoch year → year-window issue", _hasKind(rv, "year-window"));
}

function testValidateNaiveDatetimeStrict() {
  // No offset — strict refuses (cross-region ambiguity class).
  var rv = b.guardTime.validate("2026-05-05T12:34:56", { profile: "strict" });
  check("naive datetime under strict → ok:false", rv.ok === false);
  check("naive datetime → naive-datetime issue", _hasKind(rv, "naive-datetime"));
}

function testValidateNonStringReturnsBadInput() {
  // validate never throws on hostile input — it returns a bad-input issue.
  var rv = b.guardTime.validate(1234567890, { profile: "strict" });
  check("non-string input → ok:false, no throw", rv.ok === false);
  check("non-string input → bad-input issue", _hasKind(rv, "bad-input"));
}

function testSanitizeNormalizes() {
  // Legacy space separator + lowercase `z` are normalized to `T` / `Z`.
  var out = b.guardTime.sanitize("2026-05-05 12:34:56z", { profile: "balanced" });
  check("sanitize normalizes space+z → T+Z", out === "2026-05-05T12:34:56Z");
}

function testSanitizeCleanPassthrough() {
  var out = b.guardTime.sanitize("2026-05-05T12:34:56Z", { profile: "strict" });
  check("already-canonical UTC datetime passes through", out === "2026-05-05T12:34:56Z");
}

function testSanitizeThrowsOnLeapSecondStrict() {
  // Second field 60 is RFC 3339 §5.6 valid but refused under strict.
  check("leap-second refused under strict sanitize",
    _code(function () { b.guardTime.sanitize("9999-12-31T23:59:60Z", { profile: "strict" }); })
      === "time.leap-second");
}

function run() {
  testGuardTimeSurface();
  testValidateAcceptsUtcDatetime();
  testValidatePreEpochYearWindow();
  testValidateNaiveDatetimeStrict();
  testValidateNonStringReturnsBadInput();
  testSanitizeNormalizes();
  testSanitizeCleanPassthrough();
  testSanitizeThrowsOnLeapSecondStrict();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[guard-time] OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}
