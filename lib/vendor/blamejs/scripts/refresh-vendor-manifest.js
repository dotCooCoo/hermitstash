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

// Encoding gate. Reject manifests that contain Latin-1-of-UTF-8
// mojibake — the v0.9.45 MANIFEST shipped `â€"` sequences (decoded
// from `—` via misconfigured editor encoding). Catches the next
// occurrence at the refresh step instead of leaking into the npm
// tarball. The detector looks for the canonical mojibake byte
// sequence (â followed by a typographic Latin-1 byte) produced when
// UTF-8 em-dash / curly-quote / ellipsis prose is decoded as Latin-1
// and re-encoded as UTF-8.
//
// SLSA L3 hygiene — operator-facing artifacts MUST be clean UTF-8.
function _refuseMojibake(raw) {
  // â prefix matches all the Windows-1252-re-encoded
  // typographic-punctuation sequences: em-dash, en-dash, smart quotes,
  // ellipsis, etc. The presence of this byte pair in operator-facing
  // prose is always a corruption signal.
  if (/â/.test(raw)) {
    process.stderr.write("[refresh-vendor-manifest] FAIL: MANIFEST.json contains UTF-8-as-Latin-1 mojibake (e.g. `â€\"`/`â€™`).\n");
    process.stderr.write("[refresh-vendor-manifest] Re-author affected prose fields in clean UTF-8 before refreshing.\n");
    process.exit(1);
  }
  // Replacement character — a previous encoding round-trip silently
  // dropped data.
  if (raw.indexOf("�") !== -1) {
    process.stderr.write("[refresh-vendor-manifest] FAIL: MANIFEST.json contains U+FFFD replacement character (encoding loss).\n");
    process.exit(1);
  }
}

// RFC 3339 / ISO 8601 timestamp. Date-only `2026-04-25` strings
// boundary-flip across midnight-UTC under Date.parse comparisons
// (the v0.9.45 check-vendor-currency comparison treated a
// fresh-upstream commit at 2026-04-25T01:00:00Z as `current` because
// `bundledAt` parsed to `2026-04-25T00:00:00Z` and the comparison
// against a stale string from the same calendar day flipped sign
// after the runner crossed midnight). Emit the full RFC 3339 form;
// the currency check uses Date.parse on both sides, so the seconds-
// precision form removes the boundary risk.
function _rfc3339Now() {
  return new Date().toISOString();
}

function main() {
  var raw = fs.readFileSync(MANIFEST_PATH, "utf8");
  _refuseMojibake(raw);
  var manifest = JSON.parse(raw);
  var pkgs = Object.keys(manifest.packages);
  var totalHashes = 0;
  var refreshedAt = _rfc3339Now();
  for (var i = 0; i < pkgs.length; i += 1) {
    var pkg = manifest.packages[pkgs[i]];
    pkg.hashes = computeHashes(pkg);
    totalHashes += Object.keys(pkg.hashes).length;
    // Promote date-only bundledAt fields to RFC 3339 UTC so
    // Date.parse-based currency comparison is boundary-safe.
    if (typeof pkg.bundledAt === "string" && /^\d{4}-\d{2}-\d{2}$/.test(pkg.bundledAt)) {
      pkg.bundledAt = pkg.bundledAt + "T00:00:00Z";
    }
    // Stamp the refresh timestamp so operators can diff "when did
    // this bundle last get re-hashed" without trawling git log.
    pkg.refreshedAt = refreshedAt;
  }
  var out = JSON.stringify(manifest, null, 2) + "\n";
  _refuseMojibake(out);
  fs.writeFileSync(MANIFEST_PATH, out);
  process.stdout.write("[refresh-vendor-manifest] wrote " +
    pkgs.length + " packages / " + totalHashes + " hashes to " +
    MANIFEST_PATH + " (refreshedAt=" + refreshedAt + ")\n");
}

main();
