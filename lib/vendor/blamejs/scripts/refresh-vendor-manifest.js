"use strict";
/**
 * scripts/refresh-vendor-manifest.js
 *
 * Recomputes SHA-256 over every vendored file declared in
 * lib/vendor/MANIFEST.json and writes the hashes back to the
 * manifest. Operator runs this after `scripts/vendor-update.sh`
 * bumps a vendored package.
 *
 * Verification (catching drift between the manifest's recorded
 * hashes and the on-disk content) is done by the smoke gate at
 * test/layer-0-primitives/vendor-manifest.test.js — running on
 * every smoke + every CI run. This script is the refresh-tool side
 * only.
 *
 *   node scripts/refresh-vendor-manifest.js
 */

var fs = require("fs");
var crypto = require("crypto");
var path = require("path");

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

function main() {
  var manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
  var pkgs = Object.keys(manifest.packages);
  var totalHashes = 0;
  for (var i = 0; i < pkgs.length; i += 1) {
    var pkg = manifest.packages[pkgs[i]];
    pkg.hashes = computeHashes(pkg);
    totalHashes += Object.keys(pkg.hashes).length;
  }
  fs.writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + "\n");
  process.stdout.write("[refresh-vendor-manifest] wrote " +
    pkgs.length + " packages / " + totalHashes + " hashes to " +
    MANIFEST_PATH + "\n");
}

main();
