// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.guardRegex — ReDoS screening for operator-supplied patterns. Covers the
 * nested-quantifier detector's true positives AND the linear shapes it must NOT
 * false-refuse (#432 / #429): a quantified non-capturing group (`(?:…)?`,
 * `(?:…)*`) and an OPTIONAL quantified group (`(X+)?`, `(?:X+)?`) repeat the
 * group at most once, so they are linear, not catastrophic. The catastrophic
 * class requires the OUTER quantifier to be unbounded (`*`/`+`/`{n,}`).
 *
 * Run standalone: `node test/layer-0-primitives/guard-regex.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function assertSafeAccepts(src) {
  try { b.guardRegex.assertSafe(new RegExp(src), "x"); return true; } catch (_e) { return false; }
}
function sanitizeAccepts(src) {
  try { b.guardRegex.sanitize(src); return true; } catch (_e) { return false; }
}

// ---- #432 / #429: linear shapes must be ACCEPTED (were false-refused) ----
function testLinearShapesAccepted() {
  var linear = [
    "^(?:/page/\\d+)?$",            // optional non-capturing group
    "^foo(?:bar)*$",               // quantified non-capturing group
    "^foo(?:bar)?$",
    "^(a+)?$",                     // optional quantified group — repeats 0..1
    "(?:[-+][0-9A-Za-z.-]+)?",     // optional group with inner quantifier (#429)
    "(?:[-+][0-9A-Za-z.-]{1,64})?",
    "v\\d+\\.\\d+\\.\\d+(?:[-+][0-9A-Za-z.-]+)?-linux-x64",
  ];
  linear.forEach(function (src) {
    check("assertSafe accepts linear " + JSON.stringify(src), assertSafeAccepts(src));
    check("sanitize accepts linear " + JSON.stringify(src), sanitizeAccepts(src));
  });
}

// ---- genuine nested-UNBOUNDED shapes must still be REFUSED ----
function testCatastrophicShapesRefused() {
  var bad = ["^(a+)+$", "(a+)*", "((a)+)+", "(([a-z]+)*)*", "(a+){2,}"];
  bad.forEach(function (src) {
    check("assertSafe refuses catastrophic " + JSON.stringify(src), assertSafeAccepts(src) === false);
  });
}

// ---- other ReDoS classes the guard covers stay covered ----
function testOtherClasses() {
  check("alternation-with-quantifier refused", assertSafeAccepts("^(a|b|c)+$") === false);
  check("plain linear pattern accepted", assertSafeAccepts("^[a-z0-9_-]{1,64}$"));
  check("anchored alternation without group-quantifier accepted", assertSafeAccepts("^(?:cat|dog|bird)$"));
}

// ---- b.guardRegex.gate — the request-boundary screener ----
// The gate reads ctx.identifier (or ctx.pattern) and maps validate's
// severity to serve / audit-only / refuse before any new RegExp() compile.
async function testGate() {
  var gate = b.guardRegex.gate({ profile: "strict" });

  var clean = await gate.check({ identifier: "^[a-z]+$" });
  check("gate: linear pattern → action=serve, ok=true",
    clean.ok === true && clean.action === "serve");

  var nested = await gate.check({ identifier: "(a+)+b" });
  check("gate: nested-quantifier ReDoS → action=refuse, ok=false",
    nested.ok === false && nested.action === "refuse");
  check("gate: nested-quantifier → nested-quantifier issue",
    nested.issues.some(function (i) { return i.kind === "nested-quantifier"; }));

  // ctx.pattern is the documented fallback field for the pattern.
  var alt = await gate.check({ pattern: "(a|b|c)+" });
  check("gate: alternation-with-quantifier via ctx.pattern → refuse",
    alt.action === "refuse");

  // Absent pattern is a no-op serve (nothing to screen).
  var none = await gate.check({});
  check("gate: no pattern supplied → action=serve",
    none.ok === true && none.action === "serve");
}

async function run() {
  testLinearShapesAccepted();
  testCatastrophicShapesRefused();
  testOtherClasses();
  await testGate();
}

if (require.main === module) {
  run()
    .then(function () { console.log("guard-regex OK — " + helpers.getChecks() + " checks"); })
    .catch(function (e) { console.error("FAIL:", e.stack || e); process.exit(1); });
}

module.exports = { run: run };
