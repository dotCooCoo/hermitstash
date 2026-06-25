#!/usr/bin/env node
// refresh-blamejs-sbom.js — Project the vendored blamejs tree's own dependency
// manifest into the top-level SBOM so Trivy / Grype scan an accurate inventory.
//
// blamejs bundles its own crypto / identity dependencies (the noble suite,
// @simplewebauthn/server, peculiar-pki, the SecLists password set, the public
// suffix list, the BIMI trust anchors) and ships a manifest enumerating them at
// lib/vendor/blamejs/lib/vendor/MANIFEST.json. The top-level
// lib/vendor/MANIFEST.json mirrors that inventory under
// packages.blamejs.components so a single scan of the HermitStash tree sees
// every transitive package and version.
//
// That mirror used to be hand-maintained, so a blamejs bump that changed a
// nested version — or added a new bundled package — left the top-level SBOM
// silently stale or incomplete (the BIMI anchors and public suffix list were
// absent entirely). This script makes the mirror a mechanical projection of the
// vendored tree, run as the last step of `vendor-update.sh blamejs`, so the
// inventory is always exactly what is on disk.
//
// It also syncs the operator-facing docs that hard-code the blamejs version
// (README.md dependency table + THIRD_PARTY_LICENSES.md) from the same MANIFEST,
// and verifies THIRD_PARTY lists every vendored package — those drifted for the
// same hand-maintained reason (the version was stale and two packages were absent).
//
// Usage:
//   node scripts/refresh-blamejs-sbom.js            # rewrite components + sync README/THIRD_PARTY versions
//   node scripts/refresh-blamejs-sbom.js --check    # exit non-zero if the SBOM OR the docs are stale (gate)

"use strict";

var fs = require("fs");
var path = require("path");

var REPO = path.resolve(__dirname, "..");
var PARENT_MANIFEST = path.join(REPO, "lib", "vendor", "MANIFEST.json");
var NESTED_MANIFEST = path.join(REPO, "lib", "vendor", "blamejs", "lib", "vendor", "MANIFEST.json");

// Operator-facing docs that hard-code the vendored blamejs version — they drifted
// (stuck at an old version, missing newly-bundled packages) for the same reason
// the SBOM did, so they are synced from the MANIFEST here too.
var README_DOC = path.join(REPO, "README.md");
var THIRD_PARTY_DOC = path.join(REPO, "THIRD_PARTY_LICENSES.md");
// The blamejs version appears as the version cell of the README dependency-table
// row and as the THIRD_PARTY section header. Each capture group 2 is the version.
var DOC_VERSION_SITES = [
  { file: README_DOC, label: "README.md", re: /(\| \[`blamejs`\]\(https:\/\/github\.com\/blamejs\/blamejs\) \| )(\d+\.\d+\.\d+)( )/ },
  { file: THIRD_PARTY_DOC, label: "THIRD_PARTY_LICENSES.md", re: /(## blamejs v)(\d+\.\d+\.\d+)/ },
];

// Vendored-tree path, relative to the HermitStash repo root, that a nested
// manifest path (relative to the blamejs package root) resolves to.
var BLAMEJS_PREFIX = "lib/vendor/blamejs/";

// SBOM-identity fields carried from the nested manifest into the top-level
// component entry, in a stable emit order. Deliberately excludes blamejs's
// internal bookkeeping (hashes, bundler, bundledAt, refreshedAt) — those churn
// every blamejs release and say nothing about which package+version is present,
// which is all a CVE scanner needs.
var CARRIED_FIELDS = ["version", "license", "author", "source", "cpe", "exports", "components"];

// Build the top-level components object as a faithful projection of the nested
// manifest's packages, in the nested manifest's own key order (deterministic).
function projectComponents(nested) {
  if (!nested || typeof nested.packages !== "object" || nested.packages === null) {
    throw new Error("nested blamejs manifest has no packages object: " + NESTED_MANIFEST);
  }
  var out = {};
  Object.keys(nested.packages).forEach(function (name) {
    var src = nested.packages[name];
    var entry = {};
    CARRIED_FIELDS.forEach(function (field) {
      if (src[field] !== undefined) entry[field] = src[field];
    });
    // Rewrite the primary on-disk path so it is valid from the HermitStash repo
    // root (the nested manifest expresses it relative to the blamejs package).
    if (src.files && typeof src.files.server === "string") {
      entry.file = BLAMEJS_PREFIX + src.files.server;
    }
    out[name] = entry;
  });
  return out;
}

function loadJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function main() {
  var check = process.argv.indexOf("--check") !== -1;

  var parent = loadJson(PARENT_MANIFEST);
  var nested = loadJson(NESTED_MANIFEST);

  if (!parent.packages || !parent.packages.blamejs) {
    console.error("ERROR: top-level MANIFEST has no packages.blamejs entry: " + PARENT_MANIFEST);
    process.exit(2);
  }

  var projected = projectComponents(nested);
  var current = parent.packages.blamejs.components || {};
  var version = parent.packages.blamejs.version;
  var sbomMatches = JSON.stringify(current) === JSON.stringify(projected);

  // Sync (or, in --check, audit) the operator docs that hard-code the blamejs
  // version / package set, from the same MANIFEST.
  var docs = syncDocs(version, projected, check);

  if (check) {
    var ok = sbomMatches && !docs.stale;
    if (sbomMatches) {
      console.log("blamejs SBOM components in sync (" + Object.keys(projected).length + " packages).");
    } else {
      console.error("ERROR: blamejs SBOM components are stale — run: node scripts/refresh-blamejs-sbom.js");
      reportDrift(current, projected);
    }
    if (docs.stale) console.error("ERROR: operator docs (README / THIRD_PARTY_LICENSES) are stale:");
    docs.messages.forEach(function (m) { console.error(m); });
    process.exit(ok ? 0 : 1);
  }

  if (sbomMatches) {
    console.log("blamejs SBOM components already current (" + Object.keys(projected).length + " packages).");
  } else {
    parent.packages.blamejs.components = projected;
    fs.writeFileSync(PARENT_MANIFEST, JSON.stringify(parent, null, 2) + "\n");
    console.log("Refreshed blamejs SBOM components → " + Object.keys(projected).length + " packages.");
    reportDrift(current, projected);
  }
  docs.messages.forEach(function (m) { console.log(m); });
}

function escapeRegExp(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

// Return the `## ` section of `text` that contains `needle` — from its own
// `## ` header down to the next `## ` header (or EOF). Used to scope a
// version-token check to ONE package's section: a document-wide substring
// search false-negatives when a token coincidentally appears in another
// package's section. Falls back to the whole text if the needle is absent.
function sectionContaining(text, needle) {
  var idx = text.indexOf(needle);
  if (idx === -1) return text;
  var hdr = text.lastIndexOf("\n## ", idx);
  var start = hdr === -1 ? 0 : hdr + 1;
  var next = text.indexOf("\n## ", idx);
  var end = next === -1 ? text.length : next;
  return text.slice(start, end);
}

// Sync the blamejs version into README + THIRD_PARTY_LICENSES, sync each nested
// package's version header in THIRD_PARTY, and verify THIRD_PARTY lists every
// vendored package. In --check mode nothing is written and `stale` reports whether
// any doc is out of sync. A version mismatch is auto-fixed on refresh; a MISSING
// package entry can't be (its license prose isn't in the MANIFEST), so it is
// reported for the maintainer to add and keeps failing --check until they do.
function syncDocs(version, components, check) {
  var stale = false;
  var messages = [];
  DOC_VERSION_SITES.forEach(function (site) {
    var text;
    try { text = fs.readFileSync(site.file, "utf8"); } catch (_e) { return; }
    var m = site.re.exec(text);
    if (!m) { messages.push("  ? " + site.label + ": blamejs version not found (pattern drift)"); stale = true; return; }
    if (m[2] === version) return;
    stale = true;
    if (check) {
      messages.push("  ~ " + site.label + ": blamejs " + m[2] + " → " + version + " (stale)");
    } else {
      fs.writeFileSync(site.file, text.replace(site.re, "$1" + version + (m[3] || "")));
      messages.push("  ✓ " + site.label + ": blamejs version → " + version);
    }
  });
  // THIRD_PARTY hard-codes each nested package's version (as a `## <pkg> vX.Y.Z`
  // section header) AND its source URL — both drift on a blamejs bump that
  // refreshes a bundled dep, for the same hand-maintained reason the SBOM did.
  // Sync the version headers and verify the source URLs in one read/write pass.
  var tp;
  try { tp = fs.readFileSync(THIRD_PARTY_DOC, "utf8"); } catch (_e) { tp = null; }
  if (tp !== null) {
    var tpStart = tp;
    Object.keys(components).forEach(function (name) {
      var ver = components[name] && components[name].version;
      var src = components[name] && components[name].source;
      // Version-header sync. Plain-semver versions whose package name is the
      // THIRD_PARTY header (`## @noble/ciphers v2.2.0`) are rewritten in place.
      // Compound / non-semver versions (a git ref like "master", peculiar-pki's
      // "2.0.0+pkijs-3.4.0") have no single clean token to rewrite, so each
      // numeric token they DO carry is staleness-checked and surfaced for a
      // hand edit rather than auto-rewritten.
      if (ver && /^\d+\.\d+\.\d+$/.test(ver)) {
        var re = new RegExp("(^## " + escapeRegExp(name) + " v)(\\d+\\.\\d+\\.\\d+)", "m");
        var mm = re.exec(tp);
        if (mm && mm[2] !== ver) {
          stale = true;
          if (check) {
            messages.push("  ~ THIRD_PARTY_LICENSES.md: " + name + " " + mm[2] + " → " + ver + " (stale)");
          } else {
            tp = tp.replace(re, "$1" + ver);
            messages.push("  ✓ THIRD_PARTY_LICENSES.md: " + name + " → " + ver);
          }
        }
      } else if (ver) {
        // Scope each numeric token to THIS package's own section (located by its
        // source URL), not the whole document — a colliding token elsewhere
        // (e.g. another package already at the bumped sub-version) would
        // otherwise mask this package's stale header and pass --check.
        var section = src ? sectionContaining(tp, src) : tp;
        (String(ver).match(/\d+\.\d+\.\d+/g) || []).forEach(function (t) {
          if (section.indexOf(t) === -1) {
            stale = true;
            messages.push("  ~ THIRD_PARTY_LICENSES.md: " + name + " version " + t + " not found in its section (compound/non-semver — update by hand)");
          }
        });
      }
      // Presence: every vendored package's source URL must appear in THIRD_PARTY.
      if (src && tp.indexOf(src) === -1) {
        stale = true;
        messages.push("  + THIRD_PARTY_LICENSES.md is missing an entry for " + name + " (" + src + ") — add it (license prose can't be auto-derived).");
      }
    });
    if (!check && tp !== tpStart) fs.writeFileSync(THIRD_PARTY_DOC, tp);
  }
  return { stale: stale, messages: messages };
}

// Exported so the regression test can assert the on-disk SBOM matches a fresh
// projection without spawning a subprocess. Paths are exported too so the test
// reads the same manifests this script does.
module.exports = {
  projectComponents: projectComponents,
  sectionContaining: sectionContaining,
  PARENT_MANIFEST: PARENT_MANIFEST,
  NESTED_MANIFEST: NESTED_MANIFEST,
  // Audit the operator docs against the MANIFEST without writing (check mode).
  // Returns { stale, messages } so the regression suite can fail on doc drift the
  // same way the release gate does.
  checkDocs: function (version, components) { return syncDocs(version, components, true); },
};

// Human-readable summary of what the refresh changed (added / removed packages,
// version moves) — surfaced on both refresh and a failing --check.
function reportDrift(current, projected) {
  var curNames = Object.keys(current);
  var newNames = Object.keys(projected);
  newNames.forEach(function (name) {
    if (curNames.indexOf(name) === -1) {
      console.log("  + added   " + name + " @ " + (projected[name].version || "?"));
    } else if (current[name].version !== projected[name].version) {
      console.log("  ~ version " + name + ": " + current[name].version + " → " + projected[name].version);
    }
  });
  curNames.forEach(function (name) {
    if (newNames.indexOf(name) === -1) {
      console.log("  - removed " + name);
    }
  });
}

// Only act when invoked as a CLI — `require()` from the regression test must not
// rewrite the manifest as a side effect.
if (require.main === module) main();
