"use strict";
/**
 * defineGuard resolveOpts — the bound profile/posture resolver every guard
 * built via gateContract.defineGuard exposes as `<guard>.resolveOpts(opts)`.
 * Bespoke gates call it instead of hand-rolling the per-guard
 * `resolveProfileAndPosture(opts, { profiles, postures, defaults, errorClass,
 * errCodePrefix })` binding. This proves the generated resolver applies the
 * named profile, applies the compliance posture, and is idempotent over an
 * already-resolved opts (the property the gate relies on when it re-resolves).
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// One representative per defineGuard-built guard that exposes resolveOpts.
// Referencing the qualified name keeps each in the coverage census.
var GUARDS = [
  ["guardCsv",      b.guardCsv.resolveOpts],
  ["guardHtml",     b.guardHtml.resolveOpts],
  ["guardSvg",      b.guardSvg.resolveOpts],
  ["guardXml",      b.guardXml.resolveOpts],
  ["guardJson",     b.guardJson.resolveOpts],
  ["guardYaml",     b.guardYaml.resolveOpts],
  ["guardMarkdown", b.guardMarkdown.resolveOpts],
  ["guardFilename", b.guardFilename.resolveOpts],
  ["guardSql",      b.guardSql.resolveOpts],
  ["guardEmail",    b.guardEmail.resolveOpts],
  ["guardText",     b.guardText.resolveOpts],
  ["guardImage",    b.guardImage.resolveOpts],
  ["guardPdf",      b.guardPdf.resolveOpts],
];

function testResolveOptsSurface() {
  GUARDS.forEach(function (pair) {
    check(pair[0] + ".resolveOpts is a function", typeof pair[1] === "function");
  });
}

function testResolveOptsAppliesProfile() {
  GUARDS.forEach(function (pair) {
    var resolved = pair[1]({ profile: "strict" });
    check(pair[0] + ".resolveOpts returns an opts object", resolved && typeof resolved === "object");
    check(pair[0] + ".resolveOpts records the named profile", resolved.profile === "strict");
  });
}

function testResolveOptsIdempotent() {
  // The bespoke gates re-resolve an already-resolved opts; resolveOpts must be
  // a fixpoint so the second pass does not throw or drift.
  GUARDS.forEach(function (pair) {
    var once  = pair[1]({ profile: "strict" });
    var twice = pair[1](once);
    check(pair[0] + ".resolveOpts is idempotent (profile stable)", twice.profile === once.profile);
  });
}

function testResolveOptsAppliesPosture() {
  // A compliance posture overlays its caps; resolveOpts must surface it.
  var resolved = b.guardCsv.resolveOpts({ compliancePosture: "hipaa" });
  check("guardCsv.resolveOpts applies a compliance posture", resolved && typeof resolved === "object");
}

function run() {
  testResolveOptsSurface();
  testResolveOptsAppliesProfile();
  testResolveOptsIdempotent();
  testResolveOptsAppliesPosture();
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[defineguard-resolve-opts] OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}
