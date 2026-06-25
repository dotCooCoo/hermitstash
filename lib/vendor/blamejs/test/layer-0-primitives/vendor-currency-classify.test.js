"use strict";
/**
 * Vendor-currency content classifier — the logic that makes Public Suffix
 * List drift visible to the release gate. The PSL (and other bare-URL data
 * vendors) carry no npm semver, so the currency checker compares an
 * embedded `// COMMIT:` sha (primary) or `// VERSION:` timestamp (fallback)
 * between the live upstream and our bundled copy. This drift was previously
 * invisible: the checker queried npm, got a 404, and still printed "OK".
 *
 * Pure unit test (no network) — drives _classifyContentCurrency directly.
 */

var helpers = require("../helpers");
var check   = helpers.check;

var cur = require("../../scripts/check-vendor-currency.js");

var PSL = cur.SPECIAL_MAP["publicsuffix-list"];

function _doc(commit, version) {
  var head = "// This Source Code Form is subject to the terms of the MPL 2.0.\n";
  if (version) head += "// VERSION: " + version + "\n";
  if (commit)  head += "// COMMIT: " + commit + "\n";
  return head + "com\nnet\norg\n";
}

function testCommitMatchIsCurrent() {
  var v = cur._classifyContentCurrency(_doc("abc1234", "2026-06-13_x"), _doc("abc1234", "2026-06-13_x"), PSL);
  check("matching COMMIT -> not stale", v.stale === false && v.basis === "commit");
}

function testCommitDifferIsStale() {
  // Upstream moved (new commit) but our bundled copy is pinned to the old
  // sha — this is exactly the PSL-rot case the gate must now catch.
  var v = cur._classifyContentCurrency(_doc("9186eee", "2026-06-13_x"), _doc("ee780bc", "2026-05-07_y"), PSL);
  check("differing COMMIT -> stale", v.stale === true && v.basis === "commit");
  check("stale verdict carries both ids", v.upstreamId === "9186eee" && v.localId === "ee780bc");
}

function testVersionFallbackWhenNoCommit() {
  // Older list snapshots predate the COMMIT header — fall back to VERSION.
  var up = cur._classifyContentCurrency(_doc(null, "2026-06-13_x"), _doc(null, "2026-05-07_y"), PSL);
  check("no COMMIT, differing VERSION -> stale via version", up.stale === true && up.basis === "version");
  var same = cur._classifyContentCurrency(_doc(null, "2026-06-13_x"), _doc(null, "2026-06-13_x"), PSL);
  check("no COMMIT, matching VERSION -> current via version", same.stale === false && same.basis === "version");
}

function testTimestampDirectionalNewerLocalNotStale() {
  // The CDN-serves-an-older-edge case. publicsuffix.org is CDN-served and
  // different edges can return an OLDER cached copy than the one we vendored.
  // Our bundle is NEWER, so it is NOT stale — but the old exact commit/version
  // inequality flagged it stale (commits differ) and failed the release gate
  // non-deterministically. With a parseable VERSION timestamp on both sides the
  // comparison is directional: only a bundle OLDER than upstream is stale.
  // RED on the old logic (basis "commit", stale true); GREEN now.
  var v = cur._classifyContentCurrency(
    _doc("9186eee", "2026-06-13_21-47-18_UTC"),   // upstream edge: older, different commit
    _doc("27a7b5d", "2026-06-22_11-46-12_UTC"),   // our bundle: newer
    PSL);
  check("local timestamp NEWER than upstream -> not stale (stale CDN edge)",
        v.stale === false && v.basis === "version-timestamp");
}

function testTimestampDirectionalOlderLocalStale() {
  // Genuine drift: upstream advanced past our bundle -> stale (gate fires).
  var v = cur._classifyContentCurrency(
    _doc("27a7b5d", "2026-06-22_11-46-12_UTC"),   // upstream: newer
    _doc("9186eee", "2026-06-13_21-47-18_UTC"),   // our bundle: older
    PSL);
  check("local timestamp OLDER than upstream -> stale", v.stale === true && v.basis === "version-timestamp");
}

function testTimestampDirectionalEqualNotStale() {
  var v = cur._classifyContentCurrency(
    _doc("27a7b5d", "2026-06-22_11-46-12_UTC"),
    _doc("27a7b5d", "2026-06-22_11-46-12_UTC"),
    PSL);
  check("equal timestamps -> not stale", v.stale === false && v.basis === "version-timestamp");
}

function testNoIdentifierThrows() {
  // Neither side yields a comparable id (e.g. upstream format changed) —
  // must throw so the caller reports registry-error, never a silent pass.
  var threw = false;
  try { cur._classifyContentCurrency(_doc(null, null), _doc(null, null), PSL); }
  catch (_e) { threw = true; }
  check("no comparable identifier -> throws (loud, not silent pass)", threw === true);
}

function testGateConfigLockedIn() {
  // The whole point: PSL is content-tracked, BIMI is an intentional skip.
  check("publicsuffix-list mapped to http-content", PSL && PSL.type === "http-content");
  check("publicsuffix-list has an upstream URL", typeof PSL.url === "string" && PSL.url.indexOf("publicsuffix.org") !== -1);
  var bimi = cur.SPECIAL_MAP["bimi-trust-anchors"];
  check("bimi-trust-anchors is a documented skip", bimi && bimi.type === "skip" && typeof bimi.reason === "string");
}

function run() {
  testCommitMatchIsCurrent();
  testCommitDifferIsStale();
  testVersionFallbackWhenNoCommit();
  testTimestampDirectionalNewerLocalNotStale();
  testTimestampDirectionalOlderLocalStale();
  testTimestampDirectionalEqualNotStale();
  testNoIdentifierThrows();
  testGateConfigLockedIn();
  console.log("[vendor-currency-classify] OK — " + helpers.getChecks() + " checks passed");
}

module.exports = { run: run };
if (require.main === module) {
  run();
}
