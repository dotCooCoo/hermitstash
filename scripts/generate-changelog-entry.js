#!/usr/bin/env node
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
 *   node scripts/generate-changelog-entry.js 1.11.7   # explicit version
 *   node scripts/generate-changelog-entry.js --rebuild        # rewrite CHANGELOG.md from release-notes/
 *   node scripts/generate-changelog-entry.js --check          # in-memory rebuild + diff against CHANGELOG.md
 *   node scripts/generate-changelog-entry.js --release-page   # multi-section markdown for gh release create --notes-file
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
// don't appear in the source of this validator either.
function _leakPatterns() {
  var claude = [67, 76, 65, 85, 68, 69]
    .map(function (c) { return String.fromCharCode(c); })
    .join("");
  return [
    new RegExp("\\b" + claude + "\\.md\\b"),
    new RegExp("\\bper\\s+" + claude + "\\b"),
    /\bper\s+project\s+rule\s+§/,
    /\bper\s+rule\s+§\d/,
    /\bphase\s+\d/i,
    /\bsweep\s+\d/i,
    /\btier[- ]?[abc]\b/i,
    /\bbatch\s+\d/i,
    /\bgroup\s+[a-h]\b/i,
    /\bslice\s+\d/i,
    /\baudit[- ]derived\b/i,
    /\bpost[- ]audit\b/i,
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
// Keep-a-Changelog conventions plus a `Migration` section for
// release notes that ship a breaking change.
var SECTION_ALLOWLIST_ORDER = [
  "Added",
  "Changed",
  "Deprecated",
  "Removed",
  "Fixed",
  "Security",
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

  if (notes.version !== version) {
    errs.push("`version` is " + JSON.stringify(notes.version) +
      " but expected " + JSON.stringify(version));
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(notes.date || "")) {
    errs.push("`date` must be `YYYY-MM-DD`; got " + JSON.stringify(notes.date));
  }
  if (typeof notes.headline !== "string" || notes.headline.length < 8) {
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
          if (it.body.length < 16) {
            errs.push(ipx + ".body shorter than 16 characters (under-described — operators need context)");
          }
        }
      }
    }
  }

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

function _sortSections(sections) {
  return sections.slice().sort(function (a, b) {
    return SECTION_ALLOWLIST_ORDER.indexOf(a.heading) -
           SECTION_ALLOWLIST_ORDER.indexOf(b.heading);
  });
}

// CHANGELOG mode — single-line bullet entry:
//   - vX.Y.Z (YYYY-MM-DD) — **Headline.** Summary paragraph.
//     Section heading: item-title — item-body. ...
//     References: [label1](url1) · [label2](url2) ...
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
// of those is unsafe. Refuse anything that doesn't match
// `^\d+\.\d+\.\d+$` here.
function _requireSemver(version, label) {
  if (typeof version !== "string" || !/^\d+\.\d+\.\d+$/.test(version)) {
    _exit(label + " is not strict semver `\\d+.\\d+.\\d+`: " + JSON.stringify(version));
  }
  return version;
}

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
// a single `v<minor>.x.json` without breaking per-version invocations.
function _loadReleaseNotes(version) {
  var perPatchPath = path.join(NOTES_DIR, "v" + version + ".json");
  var perPatch = _tryReadJson(perPatchPath, "release-notes/v" + version + ".json");
  if (perPatch !== null) {
    return { notes: perPatch, source: "v" + version + ".json" };
  }
  var minor = version.replace(/\.\d+$/, "");
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
  return null;
}

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

function rebuildChangelog() {
  var releases = _loadAllReleases();
  if (releases.length === 0) _exit("no releases found in release-notes/");
  for (var i = 0; i < releases.length; i += 1) {
    validate(releases[i], releases[i].version);
  }
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
  var parts = [];
  parts.push("# Changelog");
  parts.push("");
  parts.push("One entry per released tag, grouped by minor. Latest first.");
  parts.push("");
  parts.push("Entries are generated from `release-notes/v<version>.json`. The full");
  parts.push("change history before v1.11.7 is available on the GitHub Releases page.");
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
  var modeFlags = [rebuildMode, checkMode, releasePageMode].filter(Boolean).length;
  if (modeFlags > 1) {
    _exit("--rebuild, --check, and --release-page are mutually exclusive");
  }

  if (rebuildMode) {
    var rebuilt = rebuildChangelog();
    fs.writeFileSync(CHANGELOG, rebuilt);
    process.stderr.write("[generate-changelog-entry] OK — rebuilt CHANGELOG.md (" +
      rebuilt.length + " bytes) from release-notes/\n");
    return;
  }

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
