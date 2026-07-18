// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * guard-shell — shell-argument content-safety primitive (b.guardShell).
 *
 * Covers the pass-through-or-throw sanitize contract: a clean argument
 * returns unchanged, while an argument carrying a shell-injection shape
 * throws GuardShellError with the offending rule id. Command / process
 * substitution, backticks and newlines are refused at EVERY profile
 * (including permissive) — the RCE class is never an operator opt-in.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _code(fn) { try { fn(); return null; } catch (e) { return e && e.code; } }

function testGuardShellSurface() {
  check("guardShell is an object",           typeof b.guardShell === "object");
  check("guardShell.NAME === 'shell'",       b.guardShell.NAME === "shell");
  check("guardShell.sanitize is a function", typeof b.guardShell.sanitize === "function");
  check("guardShell registered in guardAll",
    b.guardAll.allGuards().some(function (g) { return (g.name || g.NAME) === "shell"; }));
  check("frameworkError.GuardShellError exposed",
    typeof b.frameworkError.GuardShellError === "function");
}

function testSanitizeCleanPassthrough() {
  // A metacharacter-free argument survives sanitize verbatim.
  var out = b.guardShell.sanitize("safe-arg-value", { profile: "strict" });
  check("clean arg passes through unchanged", out === "safe-arg-value");
}

function testSanitizeRefusesMetacharChain() {
  // `safe; rm -rf /` carries the POSIX `;` command separator — a shell
  // would run `rm -rf /` after the intended arg.
  check("posix metacharacter chain refused under strict",
    _code(function () { b.guardShell.sanitize("safe; rm -rf /", { profile: "strict" }); })
      === "shell.posix-metachar");
}

function testSanitizeRefusesCommandSubstitutionEveryProfile() {
  // $(...) command substitution is refused even at permissive.
  check("$(...) command substitution refused at permissive",
    _code(function () { b.guardShell.sanitize("$(whoami)", { profile: "permissive" }); })
      === "shell.dollar-substitution");
  // Backtick substitution is likewise refused at permissive.
  check("backtick substitution refused at permissive",
    _code(function () { b.guardShell.sanitize("`id`", { profile: "permissive" }); })
      === "shell.backtick");
}

function testSanitizeThrowsGuardShellError() {
  var caught = null;
  try { b.guardShell.sanitize("a|b", { profile: "strict" }); }
  catch (e) { caught = e; }
  check("sanitize throws a GuardShellError instance",
    caught instanceof b.frameworkError.GuardShellError);
}

function run() {
  testGuardShellSurface();
  testSanitizeCleanPassthrough();
  testSanitizeRefusesMetacharChain();
  testSanitizeRefusesCommandSubstitutionEveryProfile();
  testSanitizeThrowsGuardShellError();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[guard-shell] OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}
