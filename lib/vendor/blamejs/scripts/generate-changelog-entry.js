#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Generate the CHANGELOG.md section for a release from a structured
 * JSON source at `release-notes/v<version>.json`.
 *
 * The structured source enforces operator-facing shape — every field
 * has a known semantic (headline, summary, sections[].items[], etc.)
 * and runs through a leak-vocabulary validator before the markdown
 * emitter. Hand-written prose can drift into internal-process
 * narrative ("per rule §X", phase / sweep / tier vocabulary); the
 * JSON pipeline refuses such input at validation time so the
 * discipline holds by construction.
 *
 * Usage:
 *   node scripts/generate-changelog-entry.js          # version from package.json
 *   node scripts/generate-changelog-entry.js 0.11.7   # explicit version
 *
 * Outputs:
 *   - Emits the rendered Markdown to stdout.
 *   - With `--write`: replaces the existing entry block for the same
 *     version in CHANGELOG.md (or inserts a new top entry under the
 *     `## v0.<minor>.x` section).
 *
 * Validation refusals — the generator exits non-zero when:
 *   - The JSON is missing required fields.
 *   - Any string field contains a leak-vocabulary token from the
 *     LEAK_PATTERNS list below.
 *   - The version in the JSON doesn't match the requested version.
 */

var fs   = require("node:fs");
var path = require("node:path");

var ROOT          = path.resolve(__dirname, "..");
var PACKAGE_JSON  = path.join(ROOT, "package.json");
var CHANGELOG     = path.join(ROOT, "CHANGELOG.md");
var NOTES_DIR     = path.join(ROOT, "release-notes");

// LEAK_PATTERNS — tokens that signal internal-process narrative
// instead of operator-facing description. Each pattern is built at
// runtime from char-class fragments so the literal token strings
// don't appear in the source of this validator either (the same
// posture the runtime codebase-patterns detector takes).
function _leakPatterns() {
  var claude = [67, 76, 65, 85, 68, 69]
    .map(function (c) { return String.fromCharCode(c); })
    .join("");
  return [
    // Internal config-file name + rule-shorthand variants.
    new RegExp("\\b" + claude + "\\.md\\b"),
    new RegExp("\\bper\\s+" + claude + "\\b"),
    /\bper\s+project\s+rule\s+§/,
    /\bper\s+rule\s+§\d/,
    // Phase / sweep / tier numbering — internal sequencing the
    // operator doesn't share.
    /\bphase\s+\d/i,
    /\bsweep\s+\d/i,
    /\btier[- ]?[abc]\b/i,
    /\bbatch\s+\d/i,
    /\bgroup\s+[a-h]\b/i,
    /\bslice\s+\d/i,
    // "audit-derived" / "post-audit" — internal-process attribution.
    /\baudit[- ]derived\b/i,
    /\bpost[- ]audit\b/i,
    // AI-tooling vocabulary that should never reach operator-facing.
    /\b(?:anthropic|chatgpt|openai|copilot|sonnet|opus|haiku|gemini|co[- ]authored[- ]by|llm[- ]generated|ai[- ]generated)\b/i,
  ];
}

function _exit(msg) {
  process.stderr.write("[generate-changelog-entry] " + msg + "\n");
  process.exit(1);
}

function _readJson(filePath, label) {
  var raw;
  try { raw = fs.readFileSync(filePath, "utf8"); }
  catch (e) { _exit("cannot read " + label + " (" + filePath + "): " + (e && e.message || e)); }
  try { return JSON.parse(raw); }
  catch (e) { _exit("malformed JSON in " + label + " (" + filePath + "): " + (e && e.message || e)); }
}

function _scanString(value, fieldPath, patterns) {
  var hits = [];
  for (var i = 0; i < patterns.length; i += 1) {
    if (patterns[i].test(value)) {
      hits.push({ path: fieldPath, pattern: patterns[i].source });
    }
  }
  return hits;
}

function _walkForLeaks(node, basePath, patterns, out) {
  if (typeof node === "string") {
    var hits = _scanString(node, basePath, patterns);
    for (var i = 0; i < hits.length; i += 1) out.push(hits[i]);
    return;
  }
  if (Array.isArray(node)) {
    for (var j = 0; j < node.length; j += 1) {
      _walkForLeaks(node[j], basePath + "[" + j + "]", patterns, out);
    }
    return;
  }
  if (node && typeof node === "object") {
    var keys = Object.keys(node);
    for (var k = 0; k < keys.length; k += 1) {
      if (keys[k] === "$schema") continue;
      _walkForLeaks(node[keys[k]], basePath + "." + keys[k], patterns, out);
    }
  }
}

// Section heading allowlist + canonical ordering. Modeled on the
// Keep-a-Changelog conventions plus framework-specific additions
// (`Detectors`, `Migration`). Order at render-time follows this
// list regardless of the JSON's declaration order, so generated
// entries are structurally identical across releases.
var SECTION_ALLOWLIST_ORDER = [
  "Added",
  "Changed",
  "Deprecated",
  "Removed",
  "Fixed",
  "Security",
  "Detectors",
  "Migration",
];

function _fail(errors) {
  process.stderr.write("[generate-changelog-entry] FAIL:\n");
  for (var i = 0; i < errors.length; i += 1) {
    process.stderr.write("  - " + errors[i] + "\n");
  }
  process.exit(1);
}

function validate(notes, version) {
  var errs = [];

  // ---- Required top-level fields ----

  if (notes.version !== version) {
    errs.push("`version` is " + JSON.stringify(notes.version) +
      " but expected " + JSON.stringify(version));
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(notes.date || "")) {
    errs.push("`date` must be `YYYY-MM-DD`; got " + JSON.stringify(notes.date));
  }
  if (typeof notes.headline !== "string" || notes.headline.length < 8) {                // allow:raw-byte-literal — min headline length floor
    errs.push("`headline` missing or shorter than 8 characters");
  } else {
    if (/[.!?]$/.test(notes.headline)) {
      errs.push("`headline` must not end with sentence punctuation (the renderer adds the period)");
    }
    if (notes.headline !== notes.headline.trim()) {
      errs.push("`headline` has leading/trailing whitespace");
    }
    if (!/^[A-Z`]/.test(notes.headline)) {
      errs.push("`headline` must start with a capital letter or backtick (current: " +
        JSON.stringify(notes.headline.slice(0, 16)) + "...)");
    }
  }
  if (notes.summary !== undefined) {
    if (typeof notes.summary !== "string") errs.push("`summary` must be a string when present");
    else if (notes.summary !== notes.summary.trim()) errs.push("`summary` has leading/trailing whitespace");
    else if (notes.summary.length > 0 && !/[.!?]$/.test(notes.summary)) {
      errs.push("`summary` must end with sentence punctuation");
    }
  }

  // ---- Sections ----

  if (!Array.isArray(notes.sections) || notes.sections.length === 0) {
    errs.push("`sections` must be a non-empty array");
  } else {
    var seenHeadings = {};
    for (var s = 0; s < notes.sections.length; s += 1) {
      var sec = notes.sections[s];
      var pfx = "sections[" + s + "]";
      if (typeof sec.heading !== "string") {
        errs.push(pfx + ".heading missing");
        continue;
      }
      if (SECTION_ALLOWLIST_ORDER.indexOf(sec.heading) === -1) {
        errs.push(pfx + ".heading " + JSON.stringify(sec.heading) +
          " not in allowlist: " + SECTION_ALLOWLIST_ORDER.join(" / "));
      }
      if (seenHeadings[sec.heading]) {
        errs.push(pfx + ".heading " + JSON.stringify(sec.heading) +
          " duplicates an earlier section — consolidate items under one section");
      }
      seenHeadings[sec.heading] = true;
      if (!Array.isArray(sec.items) || sec.items.length === 0) {
        errs.push(pfx + " (" + sec.heading + ") `items` missing/empty");
        continue;
      }
      for (var t = 0; t < sec.items.length; t += 1) {
        var it  = sec.items[t];
        var ipx = pfx + ".items[" + t + "]";
        if (typeof it.title !== "string" || it.title.length === 0) {
          errs.push(ipx + ".title missing");
        } else {
          if (it.title !== it.title.trim()) errs.push(ipx + ".title has leading/trailing whitespace");
          if (/[.!?]$/.test(it.title))      errs.push(ipx + ".title must not end with sentence punctuation");
          if (!/^[A-Za-z`]/.test(it.title)) errs.push(ipx + ".title must start with a letter or backtick");
        }
        if (typeof it.body !== "string" || it.body.length === 0) {
          errs.push(ipx + ".body missing");
        } else {
          if (it.body !== it.body.trim()) errs.push(ipx + ".body has leading/trailing whitespace");
          if (!/[.!?]$/.test(it.body))    errs.push(ipx + ".body must end with sentence punctuation");
          if (it.body.length < 16) {                                                    // allow:raw-byte-literal — min body length floor
            errs.push(ipx + ".body shorter than 16 characters (under-described — operators need context)");
          }
        }
      }
    }
  }

  // ---- References ----

  if (notes.references !== undefined) {
    if (!Array.isArray(notes.references)) {
      errs.push("`references` must be an array when present");
    } else {
      for (var r = 0; r < notes.references.length; r += 1) {
        var ref = notes.references[r];
        var rpx = "references[" + r + "]";
        if (typeof ref.label !== "string" || ref.label.length === 0) {
          errs.push(rpx + ".label missing");
        }
        if (typeof ref.url !== "string" || !/^https:\/\//.test(ref.url)) {
          errs.push(rpx + ".url must be an https:// URL");
        }
      }
    }
  }

  // ---- Leak-vocabulary sweep ----

  var hits = [];
  _walkForLeaks(notes, "$", _leakPatterns(), hits);
  if (hits.length > 0) {
    process.stderr.write("[generate-changelog-entry] FAIL: leak-vocabulary tokens found in release-notes JSON:\n");
    for (var h = 0; h < hits.length; h += 1) {
      process.stderr.write("  " + hits[h].path + "  ←  pattern /" + hits[h].pattern + "/\n");
    }
    process.stderr.write("[generate-changelog-entry] Each field must be operator-facing. Strip internal-process narrative + rewrite.\n");
    if (errs.length > 0) _fail(errs);
    process.exit(1);
  }

  if (errs.length > 0) _fail(errs);
}

// Re-order sections to the canonical sequence at render time.
function _sortSections(sections) {
  return sections.slice().sort(function (a, b) {
    return SECTION_ALLOWLIST_ORDER.indexOf(a.heading) -
           SECTION_ALLOWLIST_ORDER.indexOf(b.heading);
  });
}

// CHANGELOG mode — single-line bullet entry matching the existing
// CHANGELOG.md prose convention:
//   - vX.Y.Z (YYYY-MM-DD) — **Headline.** Summary paragraph.
//     Section heading: item-title — item-body. ...
//     References: [label1](url1) · [label2](url2) ...
// One-line shape preserves the awk-extractor contract used by the
// workflow + the local check-changelog-extract gate.
function renderChangelogLine(notes) {
  var out = "- v" + notes.version + " (" + notes.date + ") — **" + notes.headline + ".**";
  if (notes.summary && notes.summary.length > 0) {
    out += " " + notes.summary;
  }
  var orderedSections = _sortSections(notes.sections);
  for (var s = 0; s < orderedSections.length; s += 1) {
    var sec = orderedSections[s];
    out += " **" + sec.heading + ":** ";
    var parts = sec.items.map(function (it) {
      return "*" + it.title + "* — " + it.body;
    });
    out += parts.join(" · ");
  }
  if (Array.isArray(notes.references) && notes.references.length > 0) {
    var refList = notes.references.map(function (r) {
      return "[" + r.label + "](" + r.url + ")";
    });
    out += " **References:** " + refList.join(" · ");
  }
  return out;
}

// Release-page mode — multi-section markdown for the GitHub release
// page. Uses `##` headings + bullet lists per section so each item
// renders as its own scannable card on the release page instead of a
// single dense paragraph. The workflow's gh-release-create step
// passes this output via --notes-file.
function renderReleasePage(notes) {
  var lines = [];
  lines.push("**" + notes.headline + ".**");
  lines.push("");
  if (notes.summary && notes.summary.length > 0) {
    lines.push(notes.summary);
    lines.push("");
  }
  var orderedSections = _sortSections(notes.sections);
  for (var s = 0; s < orderedSections.length; s += 1) {
    var sec = orderedSections[s];
    lines.push("## " + sec.heading);
    lines.push("");
    for (var t = 0; t < sec.items.length; t += 1) {
      var it = sec.items[t];
      // Each item: bold title, em-dash, body. One bullet per item.
      lines.push("- **" + it.title + "** — " + it.body);
    }
    lines.push("");
  }
  if (Array.isArray(notes.references) && notes.references.length > 0) {
    lines.push("## References");
    lines.push("");
    for (var r = 0; r < notes.references.length; r += 1) {
      var ref = notes.references[r];
      lines.push("- [" + ref.label + "](" + ref.url + ")");
    }
    lines.push("");
  }
  return lines.join("\n");
}

function _readPackageVersion() {
  var pkg = _readJson(PACKAGE_JSON, "package.json");
  return pkg.version;
}

// Strict semver gate at the trust boundary. Every downstream use of
// `version` builds a regex (`^- v<version> (`), a path segment, or a
// CHANGELOG splice — feeding raw operator-controlled input into any
// of those is unsafe. We refuse anything that doesn't match
// `^\d+\.\d+\.\d+$` here, so by the time it reaches the regex
// constructors the only metacharacter is `.` (which the existing
// `.replace(/\./g, "\\.")` escapes completely).
function _requireSemver(version, label) {
  if (typeof version !== "string" || !/^\d+\.\d+\.\d+$/.test(version)) {
    _exit(label + " is not strict semver `\\d+.\\d+.\\d+`: " + JSON.stringify(version));
  }
  return version;
}

// Read-without-pre-check. Replaces the existsSync→readFileSync
// pattern (TOCTOU race) with a single readFileSync that distinguishes
// ENOENT (file genuinely absent — caller decides) from other errors
// (permission denied / I/O — fail loud).
function _tryReadJson(filePath, label) {
  var raw;
  try { raw = fs.readFileSync(filePath, "utf8"); }
  catch (e) {
    if (e && e.code === "ENOENT") return null;
    _exit("cannot read " + label + " (" + filePath + "): " + (e && e.message || e));
  }
  try { return JSON.parse(raw); }
  catch (e) { _exit("malformed JSON in " + label + " (" + filePath + "): " + (e && e.message || e)); }
}

// Lookup tries the per-patch file first, then the consolidated
// minor-line rollup. This lets non-current minor lines collapse to
// a single `v<minor>.x.json` (via `scripts/consolidate-release-notes.js`)
// without breaking the generator's `node scripts/generate-changelog-entry.js
// 0.5.3`-style invocations. `version` is pre-validated as strict
// semver by `_requireSemver` at the entry point so path concatenation
// is safe.
function _loadReleaseNotes(version) {
  var perPatchPath = path.join(NOTES_DIR, "v" + version + ".json");
  var perPatch = _tryReadJson(perPatchPath, "release-notes/v" + version + ".json");
  if (perPatch !== null) {
    return { notes: perPatch, source: "v" + version + ".json" };
  }
  var minor = version.replace(/\.\d+$/, "");                                           // already-validated semver, no metachars
  var consolidatedPath = path.join(NOTES_DIR, "v" + minor + ".x.json");
  var con = _tryReadJson(consolidatedPath, "release-notes/v" + minor + ".x.json");
  if (con !== null) {
    if (!Array.isArray(con.releases)) {
      _exit("consolidated file release-notes/v" + minor + ".x.json missing `releases` array");
    }
    for (var i = 0; i < con.releases.length; i += 1) {
      if (con.releases[i] && con.releases[i].version === version) {
        return {
          notes:  con.releases[i],
          source: "v" + minor + ".x.json (releases[" + i + "])",
        };
      }
    }
    _exit("v" + version + " not found inside consolidated file " +
      "release-notes/v" + minor + ".x.json — " +
      "the rollup may be stale or the version may not exist");
  }
  _exit("cannot find release notes for v" + version + " — " +
    "looked at release-notes/v" + version + ".json AND " +
    "release-notes/v" + minor + ".x.json (neither present)");
  return null;                                                                          // unreachable
}

// Walk `release-notes/`, load every release (both per-patch and
// consolidated minor-line files), and return a flat array sorted
// newest-first.
function _loadAllReleases() {
  var entries = fs.readdirSync(NOTES_DIR);
  var all = [];
  for (var i = 0; i < entries.length; i += 1) {
    var name = entries[i];
    if (!/\.json$/.test(name)) continue;
    var conMatch = name.match(/^v(\d+\.\d+)\.x\.json$/);
    if (conMatch) {
      var con = _readJson(path.join(NOTES_DIR, name), "release-notes/" + name);
      if (!Array.isArray(con.releases)) {
        _exit("consolidated file release-notes/" + name + " missing `releases` array");
      }
      for (var r = 0; r < con.releases.length; r += 1) all.push(con.releases[r]);
      continue;
    }
    var verMatch = name.match(/^v(\d+\.\d+\.\d+)\.json$/);
    if (!verMatch) continue;
    all.push(_readJson(path.join(NOTES_DIR, name), "release-notes/" + name));
  }
  all.sort(function (a, b) {
    var ap = String(a.version).split(".").map(Number);
    var bp = String(b.version).split(".").map(Number);
    for (var k = 0; k < 3; k += 1) {
      if (ap[k] !== bp[k]) return bp[k] - ap[k];
    }
    return 0;
  });
  return all;
}

// Build the full `CHANGELOG.md` content from `release-notes/`. Every
// entry is validated through the schema + leak-vocabulary sweep
// before render, so a malformed JSON anywhere in the tree fails the
// rebuild loud (rather than producing a silently-broken markdown
// section).
//
// Output shape — preserved across releases so the workflow's awk
// extract stays stable:
//
//   # Changelog
//
//   <preamble paragraph>
//
//   ## v0.<minor>.x
//
//   - vX.Y.Z (YYYY-MM-DD) — **Headline.** ...   (newest first)
//
//   ## v0.<minor-1>.x
//   ...
function rebuildChangelog() {
  var releases = _loadAllReleases();
  if (releases.length === 0) _exit("no releases found in release-notes/");
  // Validate everything before render — refuses to emit a partially-
  // valid CHANGELOG when one JSON has drifted.
  for (var i = 0; i < releases.length; i += 1) {
    validate(releases[i], releases[i].version);
  }
  // Group by minor for the section headers.
  var byMinor = {};
  var minorOrder = [];
  for (var j = 0; j < releases.length; j += 1) {
    var v = releases[j].version;
    var minor = v.replace(/\.\d+$/, "");
    if (!byMinor[minor]) {
      byMinor[minor] = [];
      minorOrder.push(minor);
    }
    byMinor[minor].push(releases[j]);
  }
  // `releases` is already sorted newest-first → `minorOrder` follows
  // the same order (highest minor first because its first patch is
  // the newest seen). Each minor's items[] is also already sorted.
  var parts = [];
  parts.push("# Changelog");
  parts.push("");
  parts.push("One entry per released tag, grouped by minor. Latest first.");
  parts.push("");
  parts.push("Pre-1.0 the surface is intentionally evolving — every release may");
  parts.push("change something operators depend on. Read each entry before");
  parts.push("upgrading across more than a few patches at a time.");
  parts.push("");
  for (var m = 0; m < minorOrder.length; m += 1) {
    parts.push("## v" + minorOrder[m] + ".x");
    parts.push("");
    var bucket = byMinor[minorOrder[m]];
    for (var b = 0; b < bucket.length; b += 1) {
      parts.push(renderChangelogLine(bucket[b]));
      parts.push("");
    }
  }
  // Strip the trailing blank so the file ends with exactly one newline.
  while (parts.length > 0 && parts[parts.length - 1] === "") parts.pop();
  return parts.join("\n") + "\n";
}

function main() {
  var argv = process.argv.slice(2);
  var rebuildMode     = argv.indexOf("--rebuild")      !== -1;
  var checkMode       = argv.indexOf("--check")        !== -1;
  var releasePageMode = argv.indexOf("--release-page") !== -1;
  var explicitVersion = null;
  for (var a = 0; a < argv.length; a += 1) {
    if (!argv[a].startsWith("--")) { explicitVersion = argv[a]; break; }
  }
  // Mode arbitration — every pair must be exclusive.
  var modeFlags = [rebuildMode, checkMode, releasePageMode].filter(Boolean).length;
  if (modeFlags > 1) {
    _exit("--rebuild, --check, and --release-page are mutually exclusive");
  }

  // --rebuild: regenerate the entire CHANGELOG.md from release-notes/.
  // The single source of truth is the JSON tree; the markdown is a
  // derived artifact. Operators run this whenever a release-notes
  // JSON lands (or changes), then commit both.
  if (rebuildMode) {
    var rebuilt = rebuildChangelog();
    fs.writeFileSync(CHANGELOG, rebuilt);
    process.stderr.write("[generate-changelog-entry] OK — rebuilt CHANGELOG.md (" +
      rebuilt.length + " bytes) from release-notes/\n");
    return;
  }

  // --check: in-memory rebuild + diff against on-disk. Non-mutating.
  // Smoke wires this gate so any release-notes JSON change without a
  // matching `--rebuild` fails pre-push. Line endings are normalized
  // to LF before comparison so the gate doesn't false-trip on
  // Windows runners where `git checkout` rewrites LF → CRLF (the
  // rebuilder always emits LF; both sides reduce to the same
  // canonical form for the equality check).
  if (checkMode) {
    var expected = rebuildChangelog();
    var actual;
    try { actual = fs.readFileSync(CHANGELOG, "utf8"); }
    catch (e) {
      if (e && e.code === "ENOENT") _exit("CHANGELOG.md does not exist");
      _exit("cannot read CHANGELOG.md: " + (e && e.message || e));
    }
    if (expected.replace(/\r\n/g, "\n") === actual.replace(/\r\n/g, "\n")) {
      process.stderr.write("[generate-changelog-entry] OK — CHANGELOG.md matches the rebuild from release-notes/\n");
      return;
    }
    _exit("CHANGELOG.md drifts from release-notes/ — run `node scripts/generate-changelog-entry.js --rebuild` to regenerate (then commit both)");
  }

  // Per-version modes (default render-to-stdout, or --release-page
  // for the multi-section GitHub-release markdown).
  var version = _requireSemver(
    explicitVersion || _readPackageVersion(),
    explicitVersion ? "argv[1] (explicit version)" : "package.json#version"
  );
  var loaded = _loadReleaseNotes(version);
  var notes  = loaded.notes;
  validate(notes, version);

  if (releasePageMode) {
    var releaseMd = renderReleasePage(notes);
    process.stdout.write(releaseMd);
    process.stderr.write("[generate-changelog-entry] OK — rendered v" + version +
      " release-page markdown (" + releaseMd.length + " chars)\n");
    return;
  }

  var rendered = renderChangelogLine(notes);
  process.stdout.write(rendered + "\n");
  process.stderr.write("[generate-changelog-entry] OK — rendered v" + version +
    " entry (" + rendered.length + " chars). Use --rebuild to write CHANGELOG.md, " +
    "--check to gate drift, --release-page to emit GH-release-page markdown.\n");
}

main();
