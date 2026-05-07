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
  }
  check("vendor manifest: scanned at least one hash",
        totalHashes > 0);
}

module.exports = { run: run };

if (require.main === module) {
  run();
  process.stdout.write("OK — vendor-manifest passed\n");
}
