#!/usr/bin/env node
"use strict";
/**
 * Roll up per-patch `release-notes/v<X>.<Y>.<Z>.json` files for any
 * MINOR line OTHER than the current one into a single consolidated
 * `release-notes/v<X>.<Y>.x.json` file. The current minor (derived
 * from `package.json#version`) stays as per-patch files so the
 * release-flow generator can edit a single small JSON for the live
 * line.
 *
 * Run as a MAINTAINER-SIDE step BETWEEN releases — never inside the
 * release flow. Reorganising release-notes/ mid-release would shift
 * the tarball file set after the SHA-256 / SHA3-512 / ML-DSA digests
 * were already computed.
 *
 * Consolidated file shape:
 *   {
 *     "minor":   "1.10",
 *     "releases": [
 *       { ...same shape as a single v<V>.json... },
 *       ...                    // newest first
 *     ]
 *   }
 *
 * `generate-changelog-entry.js`'s lookup falls back to the
 * consolidated file when the per-patch file is absent, so deleting
 * per-patch files after rollup (`--prune`) keeps the generator
 * working for the historical line.
 *
 * Usage:
 *   node scripts/consolidate-release-notes.js              # preview — writes consolidated files but keeps per-patch
 *   node scripts/consolidate-release-notes.js --prune      # also delete per-patch files after writing consolidated
 *   node scripts/consolidate-release-notes.js --check      # exit non-zero if any rollup is needed (CI use)
 *
 * Idempotent: re-running is safe.
 */

var fs   = require("node:fs");
var path = require("node:path");

var ROOT         = path.resolve(__dirname, "..");
var NOTES_DIR    = path.join(ROOT, "release-notes");
var PACKAGE_JSON = path.join(ROOT, "package.json");

function _exit(msg) {
  process.stderr.write("[consolidate-release-notes] " + msg + "\n");
  process.exit(1);
}

function _readJson(filePath, label) {
  var raw;
  try { raw = fs.readFileSync(filePath, "utf8"); }
  catch (e) { _exit("cannot read " + label + " (" + filePath + "): " + (e && e.message || e)); }
  try { return JSON.parse(raw); }
  catch (e) { _exit("malformed JSON in " + label + " (" + filePath + "): " + (e && e.message || e)); }
}

function _currentMinor() {
  var pkg = _readJson(PACKAGE_JSON, "package.json");
  var m = String(pkg.version || "").match(/^(\d+\.\d+)\.\d+$/);
  if (!m) _exit("could not parse minor line from package.json#version: " + JSON.stringify(pkg.version));
  return m[1];
}

function _compareVersionsDesc(a, b) {
  var ap = a.split(".").map(Number);
  var bp = b.split(".").map(Number);
  for (var i = 0; i < 3; i += 1) {
    if (ap[i] !== bp[i]) return bp[i] - ap[i];
  }
  return 0;
}

function _scan() {
  var perPatchByMinor    = {};
  var consolidatedByMinor = {};
  var entries = fs.readdirSync(NOTES_DIR);
  for (var i = 0; i < entries.length; i += 1) {
    var name = entries[i];
    if (!/\.json$/.test(name)) continue;
    var conMatch = name.match(/^v(\d+\.\d+)\.x\.json$/);
    if (conMatch) {
      consolidatedByMinor[conMatch[1]] = name;
      continue;
    }
    var verMatch = name.match(/^v(\d+)\.(\d+)\.(\d+)\.json$/);
    if (!verMatch) continue;
    var minor   = verMatch[1] + "." + verMatch[2];
    var version = verMatch[1] + "." + verMatch[2] + "." + verMatch[3];
    var payload = _readJson(path.join(NOTES_DIR, name),
      "release-notes/" + name);
    if (!perPatchByMinor[minor]) perPatchByMinor[minor] = [];
    perPatchByMinor[minor].push({ version: version, file: name, payload: payload });
  }
  Object.keys(perPatchByMinor).forEach(function (minor) {
    perPatchByMinor[minor].sort(function (a, b) {
      return _compareVersionsDesc(a.version, b.version);
    });
  });
  return { perPatchByMinor: perPatchByMinor, consolidatedByMinor: consolidatedByMinor };
}

function _stripTopSchema(obj) {
  if (obj && typeof obj === "object" && !Array.isArray(obj)) {
    var keys = Object.keys(obj);
    var out  = {};
    for (var i = 0; i < keys.length; i += 1) {
      if (keys[i] === "$schema") continue;
      out[keys[i]] = obj[keys[i]];
    }
    return out;
  }
  return obj;
}

function main() {
  var prune    = process.argv.indexOf("--prune") !== -1;
  var checkOnly = process.argv.indexOf("--check") !== -1;
  if (prune && checkOnly) _exit("--prune and --check are mutually exclusive");

  try { fs.readdirSync(NOTES_DIR); }
  catch (e) {
    if (e && e.code === "ENOENT") _exit("release-notes/ does not exist");
    _exit("cannot read release-notes/: " + (e && e.message || e));
  }

  var current = _currentMinor();
  var scan    = _scan();
  var minors  = Object.keys(scan.perPatchByMinor).sort();

  if (minors.length === 0 &&
      Object.keys(scan.consolidatedByMinor).length === 0) {
    _exit("no per-version OR consolidated release notes found in " +
      path.relative(ROOT, NOTES_DIR));
  }

  var wouldRollup = [];
  var rolledUp   = [];
  var pruned     = 0;
  var skipped    = [];

  for (var i = 0; i < minors.length; i += 1) {
    var minor    = minors[i];
    var releases = scan.perPatchByMinor[minor];
    if (minor === current) {
      skipped.push(minor + ".x (current minor — " + releases.length + " per-patch files preserved)");
      continue;
    }
    wouldRollup.push({ minor: minor, count: releases.length });
    if (checkOnly) continue;

    var consolidated = {
      "minor":    minor,
      "releases": releases.map(function (e) { return _stripTopSchema(e.payload); }),
    };
    var outPath = path.join(NOTES_DIR, "v" + minor + ".x.json");
    fs.writeFileSync(outPath, JSON.stringify(consolidated, null, 2) + "\n");
    rolledUp.push(minor + ".x (" + releases.length + " releases → v" + minor + ".x.json)");

    if (prune) {
      for (var j = 0; j < releases.length; j += 1) {
        fs.unlinkSync(path.join(NOTES_DIR, releases[j].file));
        pruned += 1;
      }
    }
  }

  if (scan.consolidatedByMinor[current]) {
    process.stderr.write("[consolidate-release-notes] WARN — release-notes/" +
      scan.consolidatedByMinor[current] + " exists for the CURRENT minor (" +
      current + "). The current minor is supposed to stay per-patch. " +
      "Hand-merge any unique releases back into per-patch files, then delete the consolidated file.\n");
  }

  if (checkOnly) {
    if (wouldRollup.length > 0) {
      process.stderr.write("[consolidate-release-notes] CHECK FAIL — " +
        wouldRollup.length + " non-current minor line(s) still in per-patch shape:\n");
      for (var c = 0; c < wouldRollup.length; c += 1) {
        process.stderr.write("  " + wouldRollup[c].minor + ".x (" + wouldRollup[c].count + " per-patch files)\n");
      }
      process.stderr.write("[consolidate-release-notes] Run `node scripts/consolidate-release-notes.js --prune` to roll them up.\n");
      process.exit(1);
    }
    process.stderr.write("[consolidate-release-notes] OK — every non-current minor is already consolidated.\n");
    return;
  }

  for (var s = 0; s < skipped.length; s += 1) {
    process.stderr.write("[consolidate-release-notes] SKIP   " + skipped[s] + "\n");
  }
  for (var r = 0; r < rolledUp.length; r += 1) {
    process.stderr.write("[consolidate-release-notes] WROTE  " + rolledUp[r] + "\n");
  }
  process.stderr.write("[consolidate-release-notes] DONE — wrote " + rolledUp.length +
    " consolidated file(s), skipped " + skipped.length +
    " (current minor), pruned " + pruned + " per-patch file(s)" +
    (prune ? "" : " — pass `--prune` to delete per-patch files after consolidation") + "\n");
}

main();
