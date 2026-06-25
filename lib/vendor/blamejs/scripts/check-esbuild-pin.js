#!/usr/bin/env node
"use strict";

// Enforces that the SEA-build tool versions installed across the build artifacts
// agree, and that the pinned esbuild version carries a COMPLETE reviewed
// binary-hash entry. Single shared checker, two callers: release.js regen runs
// the CLI; the codebase-patterns esbuild-pin-cross-artifact-drift detector
// requires checkEsbuildPin() so the same logic gates every PR.
//
// Why this exists: the smoke gate (bundler-output.test.js) verifies the esbuild
// native binary against the pin, but on a version it has no hash for it NOTES +
// SKIPS rather than failing (it can only verify what was reviewed). That is the
// correct runtime behaviour, but it means bumping esbuild while forgetting to
// capture + commit the new version's hashes silently downgrades the pin to a
// skip. This turns that omission into a hard failure: the version package.json /
// ci.yml / npm-publish.yml install MUST have a complete reviewed-hash entry. It
// VERIFIES the pin is present; it never derives it (deriving-and-trusting would
// record whatever npm served, defeating the pin).
//
// package.json devDependencies is the single version source of truth (Dependabot
// tracks it); esbuild-binary-pin.json carries only the reviewed hashes.

var fs = require("node:fs");
var path = require("node:path");

var ROOT = path.resolve(__dirname, "..");
var PIN_PATH = path.join(__dirname, "esbuild-binary-pin.json");
var HEX64_RE = /^[0-9a-f]{64}$/;

// Workflows whose SEA-build step installs the pinned tool versions. Each MUST
// carry an exact `<tool>@<version>` spec for every required tool: an install
// line that drops the version (e.g. `npm install esbuild postject`) would let CI
// resolve an unreviewed esbuild and silently fall back to the binary-hash smoke
// gate's skip path, so a missing pinned spec is itself a violation (fail-closed).
// If the SEA build legitimately moves out of one of these, update this list in
// the same change.
var WORKFLOWS = [
  ".github/workflows/ci.yml",
  ".github/workflows/npm-publish.yml",
];
var REQUIRED_TOOLS = ["esbuild", "postject"];

// Returns { ok: boolean, violations: [{ file, line, content }] }. Never throws on
// expected-missing inputs — a missing file is reported as a violation so the
// caller surfaces it rather than passing silently.
function checkEsbuildPin() {
  var bad = [];
  var push = function (file, content) { bad.push({ file: file, line: 0, content: content }); };

  var pkg;
  try { pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")); }
  catch (e) { push("package.json", "unreadable: " + (e && e.message)); return { ok: false, violations: bad }; }
  var dev = pkg.devDependencies || {};
  var esbuildVer = dev.esbuild;
  var postjectVer = dev.postject;
  if (!esbuildVer) push("package.json", "devDependencies.esbuild missing — it is the SEA-build version pin");
  if (!postjectVer) push("package.json", "devDependencies.postject missing — it is the SEA-build version pin");

  var pin;
  try { pin = JSON.parse(fs.readFileSync(PIN_PATH, "utf8")); }
  catch (e) { push("scripts/esbuild-binary-pin.json", "unreadable: " + (e && e.message)); return { ok: false, violations: bad }; }
  var requiredPlatforms = pin.requiredPlatforms || [];
  var binarySha256 = pin.binarySha256 || {};

  // The pinned esbuild version carries a reviewed hash for every required
  // platform floor, each a 64-char lowercase hex digest.
  if (esbuildVer) {
    var verMap = binarySha256[esbuildVer];
    if (!verMap || typeof verMap !== "object") {
      push("scripts/esbuild-binary-pin.json",
        "no binarySha256 entry for the pinned esbuild " + esbuildVer +
        " (package.json devDep) — re-review the published-tarball diff + add the per-platform binary hashes on bump");
    } else {
      requiredPlatforms.forEach(function (plat) {
        var h = verMap[plat];
        if (typeof h !== "string" || !HEX64_RE.test(h)) {
          push("scripts/esbuild-binary-pin.json",
            "esbuild " + esbuildVer + " is missing a valid reviewed SHA-256 for required platform " +
            plat + " (got " + JSON.stringify(h) + ")");
        }
      });
    }
  }

  // Every scoped workflow installs the exact package.json versions — and MUST
  // pin each required tool with a `<tool>@<version>` spec (a missing spec means
  // an unpinned, unreviewed install slips through).
  var expectedFor = { esbuild: esbuildVer, postject: postjectVer };
  WORKFLOWS.forEach(function (rel) {
    var src;
    try { src = fs.readFileSync(path.join(ROOT, rel), "utf8"); }
    catch (e) { push(rel, "unreadable: " + (e && e.message)); return; }
    REQUIRED_TOOLS.forEach(function (tool) {
      var expected = expectedFor[tool];
      if (!expected) return; // already reported as a missing package.json devDep above
      checkSpec(bad, rel, src, tool, expected);
    });
  });

  return { ok: bad.length === 0, violations: bad };
}

function checkSpec(bad, rel, src, tool, expected) {
  var re = new RegExp(tool + "@([0-9][\\w.-]*)", "g");
  var m;
  var found = [];
  while ((m = re.exec(src)) !== null) { found.push(m[1]); }
  if (found.length === 0) {
    bad.push({ file: rel, line: 0,
      content: rel + " has no pinned " + tool + "@<version> spec — the SEA-build install must pin " +
        tool + "@" + expected + " (an unpinned install resolves an unreviewed version and the " +
        "binary-hash smoke gate falls back to its skip path)" });
    return;
  }
  found.forEach(function (ver) {
    if (ver !== expected) {
      bad.push({ file: rel, line: 0,
        content: rel + " installs " + tool + "@" + ver + " but package.json devDependencies pins " +
          tool + "@" + expected + " — bump the pin (and re-review the esbuild binary hash) or fix the workflow" });
    }
  });
}

module.exports = { checkEsbuildPin: checkEsbuildPin };

if (require.main === module) {
  var res = checkEsbuildPin();
  if (!res.ok) {
    res.violations.forEach(function (v) { console.error("[check-esbuild-pin] FAIL — " + v.content); });
    process.exit(1);
  }
  console.log("[check-esbuild-pin] OK — esbuild/postject pinned consistently across package.json + " +
    WORKFLOWS.length + " workflow(s); reviewed per-platform hashes present.");
}
