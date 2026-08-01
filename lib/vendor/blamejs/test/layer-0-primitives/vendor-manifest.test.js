// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * vendor-manifest.test.js
 *
 * Smoke-time gate that verifies every vendored file declared in
 * lib/vendor/MANIFEST.json matches the SHA-256 hash committed
 * alongside it. Closes the supply-chain class where a compromised
 * scripts/vendor-update.sh could swap a vendored dependency silently.
 *
 * The standalone gate at scripts/check-vendor-manifest.js exists too
 * (release-workflow + CI step); this duplicate sweep ensures
 * operators running `node test/smoke.js` locally catch hash drift
 * before commit, not at CI.
 */

var fs = require("fs");
var crypto = require("crypto");
var path = require("path");
var check = require("../helpers/check").check;

var MANIFEST_PATH = "lib/vendor/MANIFEST.json";

function hashFile(p) {
  return "sha256:" + crypto.createHash("sha256")
    .update(fs.readFileSync(p)).digest("hex");
}

function hashTree(dir) {
  var entries = fs.readdirSync(dir, { withFileTypes: true })
    .sort(function (a, b) { return a.name.localeCompare(b.name); });
  var h = crypto.createHash("sha256");
  for (var i = 0; i < entries.length; i += 1) {
    var e = entries[i];
    var p = path.join(dir, e.name);
    h.update(e.name);
    if (e.isDirectory()) h.update(hashTree(p));
    else h.update(fs.readFileSync(p));
  }
  return "sha256-tree:" + h.digest("hex");
}

function computeHashes(pkgEntry) {
  if (!pkgEntry.files) return {};
  var out = {};
  var keys = Object.keys(pkgEntry.files);
  for (var i = 0; i < keys.length; i += 1) {
    var k = keys[i];
    var fp = pkgEntry.files[k];
    if (typeof fp !== "string") continue;
    if (fp.endsWith("/")) {
      if (fs.existsSync(fp)) out[k] = hashTree(fp);
    } else if (fs.existsSync(fp)) {
      out[k] = hashFile(fp);
    } else {
      out[k] = "MISSING";
    }
  }
  return out;
}

function run() {
  var manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
  var pkgs = Object.keys(manifest.packages);
  check("vendor manifest has at least one package",
        pkgs.length > 0);

  // NOTICE is the operator / compliance dependency inventory; each Component's
  // Version must match the vendored version. A re-vendor that bumped MANIFEST but
  // left NOTICE stale (five @blamejs/pki bumps did exactly that) reports a false
  // inventory — the same drift class as components[]/cpe below, on the
  // human-facing surface. vendor-update.sh now syncs it; this gates it.
  var noticeBlocks = fs.readFileSync("NOTICE", "utf8").split(Array(81).join("-"));

  var totalHashes = 0;
  for (var i = 0; i < pkgs.length; i += 1) {
    var name = pkgs[i];
    var pkg = manifest.packages[name];
    check("vendor manifest: " + name + " declares hashes",
          pkg.hashes && Object.keys(pkg.hashes).length > 0);
    var actual = computeHashes(pkg);
    var declared = pkg.hashes || {};
    var keys = Object.keys(actual);
    for (var k = 0; k < keys.length; k += 1) {
      var fk = keys[k];
      totalHashes += 1;
      check("vendor manifest: " + name + " :: " + fk + " hash matches",
            declared[fk] === actual[fk]);
    }

    // SBOM / CVE scanners (Trivy / Grype / a CycloneDX export) key on the
    // STRUCTURED components[<pkg>].version, not the human version string. A
    // hand-maintained components sub-object can drift from the version string
    // (#366: the bundle moved @peculiar/x509 1.13.0 -> 2.0.0, the version
    // string was updated to 2.0.0 but components still read 1.13.0, so any
    // advisory in the (1.13.0, 2.0.0] range matched the wrong version). Nothing
    // auto-derives components (refresh-vendor-manifest only refreshes hashes),
    // so gate the consistency here: every structured component version MUST
    // appear in the package's version string, making the drift un-shippable.
    if (pkg.components && typeof pkg.version === "string") {
      // Bind the structured component versions to the version string as a
      // MULTISET, not a loose substring: the sorted list of component versions
      // must equal the sorted list of semver tokens in the version string. A
      // bare "does the component version appear in the string" check would let
      // a component drift to a value that merely appears elsewhere in the string
      // — e.g. setting @peculiar/x509 to pkijs's 3.4.0 passes indexOf against
      // "2.0.0+pkijs-3.4.0" but the SBOM then reports the wrong x509 version.
      // The multiset {3.4.0,3.4.0} != {2.0.0,3.4.0} catches it.
      var compVers = Object.keys(pkg.components)
        .map(function (cn) { return pkg.components[cn] && pkg.components[cn].version; })
        .filter(function (v) { return typeof v === "string"; })
        .sort();
      var strVers = (pkg.version.match(/\d+\.\d+\.\d+/g) || []).slice().sort();
      check("vendor manifest: " + name + " :: components[] versions [" + compVers.join(",") +
            "] are exactly the semver tokens in the version string [" + strVers.join(",") + "]",
            compVers.length === strVers.length &&
            compVers.every(function (v, i) { return v === strVers[i]; }));
    }

    // The cpe (Common Platform Enumeration) string encodes the version in
    // field 5 (cpe:2.3:a:vendor:product:VERSION:...) and CVE scanners match
    // against it — the same SBOM-drift class as components[] (#366 sibling:
    // @noble/curves shipped 2.2.0 but its cpe still read 0.0.0). Gate it: the
    // cpe version must equal the package's (leading) semver, so a wrong-version
    // CVE match can't ship.
    if (typeof pkg.cpe === "string") {
      var cpeM = /^cpe:2\.3:a:[^:]+:[^:]+:([^:]+):/.exec(pkg.cpe);
      var cpeVer = cpeM ? cpeM[1] : null;
      var pkgSemver = (String(pkg.version).match(/\d+\.\d+\.\d+/) || [null])[0];
      if (cpeVer !== null && cpeVer !== "*" && pkgSemver !== null) {
        check("vendor manifest: " + name + " :: cpe version (" + cpeVer +
              ") matches the package version (" + pkgSemver + ")",
              cpeVer === pkgSemver);
      }
    }

    // NOTICE Version parity (when this package has a NOTICE block).
    var noticeVer = null;
    for (var nbi = 0; nbi < noticeBlocks.length; nbi += 1) {
      var cm = noticeBlocks[nbi].match(/Component:\s+(\S+)/);
      if (cm && cm[1] === name) {
        var nvM = noticeBlocks[nbi].match(/Version:\s+(\S+)/);
        noticeVer = nvM ? nvM[1] : null;
        break;
      }
    }
    if (noticeVer !== null) {
      check("vendor manifest: " + name + " :: NOTICE version (" + noticeVer +
            ") matches the manifest version (" + pkg.version + ")",
            noticeVer === pkg.version);
    }
  }
  check("vendor manifest: scanned at least one hash",
        totalHashes > 0);

  // Operator-facing license-summary consistency. The README dependency-inventory
  // ends in a one-line summary that claims the tabulated set is "All ... MIT
  // licensed" with a named exception clause. A package the README TABULATES whose
  // NOTICE License is not MIT must be named — with its license — in that clause,
  // or the published inventory misstates a dependency's license. Adding a new
  // vendored bundle to the table (an Apache-2.0 @blamejs/pki) without amending the
  // summary published "all MIT" over an Apache-2.0 dependency. Scoped to
  // README-tabulated components (matched by their exact backtick token) so the
  // full NOTICE inventory — which lists deps the README highlight omits (MPL-2.0
  // publicsuffix-list, @noble/curves) — stays authoritative on its own surface.
  var readme    = fs.readFileSync("README.md", "utf8");
  var summaryM  = readme.match(/All are MIT licensed[^\n]*\./);
  check("README carries the vendor license-summary sentence", !!summaryM);
  var summary   = summaryM ? summaryM[0] : "";
  for (var lb = 0; lb < noticeBlocks.length; lb += 1) {
    var lcM = noticeBlocks[lb].match(/Component:\s+(.+)/);
    var llM = noticeBlocks[lb].match(/License:\s+(\S+)/);
    if (!lcM || !llM) continue;
    var comp = lcM[1].trim();
    var lic  = llM[1];
    if (/^MIT$/i.test(lic)) continue;                       // MIT is the summary's default claim
    if (readme.indexOf("`" + comp + "`") < 0) continue;     // not tabulated → NOTICE is authoritative
    check("README license summary names tabulated non-MIT dep " + comp + " (" + lic + ")",
          summary.indexOf(comp) >= 0 && summary.indexOf(lic) >= 0);
  }
}

module.exports = { run: run };

if (require.main === module) {
  run();
  process.stdout.write("OK — vendor-manifest passed\n");
}
