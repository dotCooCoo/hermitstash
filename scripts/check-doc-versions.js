"use strict";

/**
 * Doc-version drift gate.
 *
 * Keeps the hand-typed version references in the operator-facing docs in
 * lockstep with their single source of truth, so a vendored-dependency bump
 * can't leave a stale version stranded in the prose.
 *
 * This exists because that is exactly what happened: a browser bundle was
 * refreshed from 2.2.0 to 2.3.0 and the README kept advertising 2.2.0, with
 * nothing to catch it. The vendoring script syncs a couple of references
 * itself, but only the ones it happens to know about — every other mention was
 * unguarded.
 *
 * Sources of truth (all in lib/vendor/MANIFEST.json + package.json):
 *   - vendored blamejs version    -> packages.blamejs.version
 *   - browser bundle versions     -> packages["@noble/*"].version
 *   - Node.js runtime floor       -> package.json (engines.node)
 *
 * Each rule anchors on a SPECIFIC phrasing, so an unrelated version on the same
 * line is never touched. Each rule must also match at least once: if the prose
 * is reworded so a rule matches nothing, the gate FAILS rather than silently
 * passing. A gate that quietly checks nothing is worse than no gate — that is
 * the failure mode this guard exists to prevent.
 *
 * Modes:
 *   node scripts/check-doc-versions.js         # gate: fail on drift (default)
 *   node scripts/check-doc-versions.js --check # same as default
 *   node scripts/check-doc-versions.js --fix   # rewrite the docs to the source
 */

var fs = require("node:fs");
var path = require("node:path");
var b = require("../lib/vendor/blamejs");

var REPO_ROOT = path.resolve(__dirname, "..");

// Operator-facing docs that carry version prose. Every rule scans all of them,
// so a reference added to one of these later is covered automatically.
var DOC_FILES = ["README.md", "THIRD_PARTY_LICENSES.md", "docs/THREAT_MODEL.md"];

function readJson(abs) {
  return b.safeJson.parse(fs.readFileSync(abs, "utf8"), { maxBytes: b.constants.BYTES.mib(1) });
}

// The authoritative versions every doc reference must agree with.
function sourcesOfTruth(repoRoot) {
  var manifest = readJson(path.join(repoRoot, "lib", "vendor", "MANIFEST.json"));
  var pkgs = (manifest && manifest.packages) || {};

  function version(name) {
    var p = pkgs[name];
    if (!p || typeof p.version !== "string") {
      throw new Error("lib/vendor/MANIFEST.json: packages[" + JSON.stringify(name) + "].version is missing");
    }
    return p.version;
  }

  var pkg = readJson(path.join(repoRoot, "package.json"));
  var nodeRange = (pkg.engines && typeof pkg.engines.node === "string") ? pkg.engines.node : "";
  var nodeFloor = nodeRange.replace(/^[\s>=~^]+/, "").trim();
  if (!/^\d+\.\d+\.\d+$/.test(nodeFloor)) {
    throw new Error('package.json engines.node ("' + nodeRange + '") is not a plain floor like ">=24.19.0"');
  }

  return {
    blamejs:     version("blamejs"),
    nobleCiphers: version("@noble/ciphers"),
    nobleHashes:  version("@noble/hashes"),
    noblePq:      version("@noble/post-quantum"),
    nodeFloor:    nodeFloor,
  };
}

// Each rule: an anchored literal regex (global, ONE capture group = the version
// token to check), the canonical value it must equal, and a label. The regexes
// are literals — never built from a string — so there is no dynamic-RegExp /
// ReDoS surface; they are consumed via matchAll/replace, which do not mutate
// the source regex's lastIndex, so a rule is safe to reuse across files.
function rulesFor(s) {
  return [
    // README vendored table + THIRD_PARTY_LICENSES heading. The table anchor is
    // the repo URL followed by the version cell, so it does not also catch the
    // prose link to the vendored source directory earlier in the README.
    { label: "vendored blamejs version",  re: /github\.com\/blamejs\/blamejs\) \| (\d+\.\d+\.\d+)/g, expect: s.blamejs },
    { label: "blamejs licence heading",   re: /## blamejs v(\d+\.\d+\.\d+)/g,                        expect: s.blamejs },
    // The browser bundles — the references that actually drifted.
    { label: "@noble/ciphers (browser)",  re: /noble-ciphers\) \(browser only\) \| (\d+\.\d+\.\d+)/g,                     expect: s.nobleCiphers },
    { label: "@noble/hashes (browser)",   re: /noble-hashes\) \(browser only\) \| (\d+\.\d+\.\d+)/g,                      expect: s.nobleHashes },
    { label: "@noble/post-quantum (browser)", re: /noble-post-quantum\) \(browser only\) \| (\d+\.\d+\.\d+)/g,            expect: s.noblePq },
    // Node floor, stated several ways across the docs.
    { label: "Node.js runtime floor",     re: /Node\.js (\d+\.\d+\.\d+)\+/g,                                              expect: s.nodeFloor },
  ];
}

// Evaluate one rule across all docs. Returns { matches, drift: [...] }.
function evalRule(repoRoot, rule) {
  var matches = 0;
  var drift = [];
  DOC_FILES.forEach(function (file) {
    var abs = path.join(repoRoot, file);
    if (!fs.existsSync(abs)) return;
    var text = fs.readFileSync(abs, "utf8");
    var found = text.matchAll(rule.re);
    for (var m of found) {
      matches++;
      if (m[1] !== rule.expect) drift.push({ file: file, found: m[1], expect: rule.expect });
    }
  });
  return { matches: matches, drift: drift };
}

function checkDocs(repoRoot) {
  repoRoot = repoRoot || REPO_ROOT;
  var s = sourcesOfTruth(repoRoot);
  var problems = [];
  rulesFor(s).forEach(function (rule) {
    var r = evalRule(repoRoot, rule);
    if (r.matches === 0) {
      problems.push('  ! "' + rule.label + '": anchor matched nothing in ' + DOC_FILES.join("/") +
        " — the prose was reworded; update the rule in scripts/check-doc-versions.js or restore the reference.");
      return;
    }
    r.drift.forEach(function (d) {
      problems.push("  ~ " + d.file + ': "' + rule.label + '" says ' + d.found + ", source of truth is " + d.expect);
    });
  });
  if (problems.length === 0) {
    process.stdout.write("[check-doc-versions] OK — operator-facing docs match blamejs " + s.blamejs +
      ", the browser bundles, and Node " + s.nodeFloor + ".\n");
    return 0;
  }
  process.stderr.write(
    "[check-doc-versions] DRIFT — operator-facing docs disagree with the source of truth:\n" +
    problems.join("\n") + "\n" +
    "  Fix: run `node scripts/check-doc-versions.js --fix` and commit.\n"
  );
  return 1;
}

// Rewrite each drifted reference in place. Only the captured version token is
// replaced, so the surrounding prose is untouched.
function fixDocs(repoRoot) {
  repoRoot = repoRoot || REPO_ROOT;
  var s = sourcesOfTruth(repoRoot);
  var rules = rulesFor(s);
  var changed = 0;
  DOC_FILES.forEach(function (file) {
    var abs = path.join(repoRoot, file);
    if (!fs.existsSync(abs)) return;
    var text = fs.readFileSync(abs, "utf8");
    var before = text;
    rules.forEach(function (rule) {
      text = text.replace(rule.re, function (whole, ver) {
        return ver === rule.expect ? whole : whole.replace(ver, rule.expect);
      });
    });
    if (text !== before) {
      fs.writeFileSync(abs, text);
      changed++;
      process.stdout.write("[check-doc-versions] rewrote " + file + "\n");
    }
  });
  process.stdout.write("[check-doc-versions] --fix touched " + changed + " file(s).\n");
  return 0;
}

if (require.main === module) {
  var mode = process.argv[2] || "--check";
  try {
    process.exit(mode === "--fix" ? fixDocs() : checkDocs());
  } catch (e) {
    process.stderr.write("[check-doc-versions] FAILED — " + (e && e.message) + "\n");
    process.exit(2);
  }
}

module.exports = { checkDocs: checkDocs, fixDocs: fixDocs, sourcesOfTruth: sourcesOfTruth };
