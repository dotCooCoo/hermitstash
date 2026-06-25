#!/usr/bin/env node
"use strict";
/**
 * Pre-push static gate — exercise the awk-extract the docker-publish
 * workflow runs at release time to pull the current version's
 * CHANGELOG section into `release-notes.md`.
 *
 * Same logic as the workflow's `Extract release notes from CHANGELOG.md`
 * step. Running it locally before tag-push means CHANGELOG format drift
 * (e.g. a new entry that doesn't match the canonical
 * `- vX.Y.Z (YYYY-MM-DD) — <summary>` shape) fails locally rather than
 * mid-workflow.
 *
 * Exit codes:
 *   0  — extract produced ≥ 1 lines AND the first line matches the
 *        canonical entry shape
 *   1  — no entry found OR entry shape malformed
 *
 * Usage:
 *   node scripts/check-changelog-extract.js          # uses package.json version
 *   node scripts/check-changelog-extract.js 1.11.7   # explicit version
 */

var fs   = require("node:fs");
var path = require("node:path");

var ROOT          = path.resolve(__dirname, "..");
var CHANGELOG     = path.join(ROOT, "CHANGELOG.md");
var PACKAGE_JSON  = path.join(ROOT, "package.json");

function readPackageVersion() {
  var raw = fs.readFileSync(PACKAGE_JSON, "utf8");
  var pkg = JSON.parse(raw);
  return pkg.version;
}

// Escape every regex metacharacter so an interpolated string is matched
// literally — the canonical escape-string-regexp shape. `version` is already
// constrained to MAJOR.MINOR.PATCH before it reaches the matcher, so this is
// belt-and-suspenders, but a complete escape (not a dots-only one) is the
// correct sanitizer regardless of how the value is constrained upstream.
function escapeRegExp(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function extractSection(text, version) {
  var lines = text.split(/\r?\n/);
  var out = [];
  var capturing = false;
  var entryStartRe = /^- v(\d+\.\d+\.\d+) \(/;
  var sectionBreakRe = /^## v\d/;
  for (var i = 0; i < lines.length; i += 1) {
    var ln = lines[i];
    var startMatch = ln.match(entryStartRe);
    if (startMatch) {
      if (startMatch[1] === version) {
        capturing = true;
        out.push(ln);
        continue;
      }
      if (capturing) break;
    }
    if (capturing && sectionBreakRe.test(ln)) break;
    if (capturing) out.push(ln);
  }
  return out;
}

function main() {
  var version = process.argv[2] || readPackageVersion();
  if (!/^\d+\.\d+\.\d+$/.test(version)) {
    console.error("[check-changelog-extract] FAIL: bad version arg: " +
      JSON.stringify(version) +
      " (expected `MAJOR.MINOR.PATCH`)");
    process.exit(1);
  }

  var text;
  try { text = fs.readFileSync(CHANGELOG, "utf8"); }
  catch (e) {
    console.error("[check-changelog-extract] FAIL: cannot read CHANGELOG.md: " +
      (e && e.message || e));
    process.exit(1);
  }

  var section = extractSection(text, version);
  if (section.length === 0) {
    console.error("[check-changelog-extract] FAIL: no CHANGELOG entry found for v" + version);
    console.error("[check-changelog-extract] Expected a line matching `- v" + version +
      " (YYYY-MM-DD) — <summary>`");
    console.error("[check-changelog-extract] The workflow's release-notes extract will produce 0 lines and refuse to publish.");
    process.exit(1);
  }

  var firstLine = section[0];
  var canonical = new RegExp(
    "^- v" + escapeRegExp(version) +
    " \\(\\d{4}-\\d{2}-\\d{2}\\) — \\S.+$"
  );
  if (!canonical.test(firstLine)) {
    console.error("[check-changelog-extract] FAIL: v" + version +
      " entry's first line does not match the canonical shape:");
    console.error("[check-changelog-extract]   expected: `- v" + version +
      " (YYYY-MM-DD) — <summary>`");
    console.error("[check-changelog-extract]   got:       " + JSON.stringify(firstLine));
    console.error("[check-changelog-extract] The workflow's release title build will fail to strip the prefix.");
    process.exit(1);
  }

  console.log("[check-changelog-extract] OK — v" + version + " entry extracts cleanly (" +
    section.length + " line(s)); first line shape canonical.");
}

main();
