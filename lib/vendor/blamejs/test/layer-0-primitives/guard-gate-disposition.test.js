// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Gate-disposition coverage — every finding kind a content guard can emit MUST
 * be classified by that guard's dispositionFor (→ refuse / sanitize / audit), so
 * buildContentGate never falls back to severity for a guard's own finding. The
 * conservative severity fallback exists only for operator-injected extraIssues
 * and as a secure backstop; this test proves it is dead code for guard findings.
 *
 * The kind set is SCANNED from each guard's source (every `kind:` literal,
 * including ternary branches) plus the shared character-threat kinds emitted by
 * codepointClass.detectCharThreats — so a NEW finding kind added to a guard
 * without a dispositionFor mapping fails this test (RED) rather than silently
 * inheriting the conservative refuse.
 */

var fs      = require("fs");
var path    = require("path");
var helpers = require("../helpers");
var check   = helpers.check;

var LIB = path.join(__dirname, "..", "..", "lib");

// Shared char-threat kinds come from codepointClass.detectCharThreats, not the
// guard source, so they are added to every content guard's expected set
// (zero-width is opt-in via the detector's 4th arg for the markup guards).
var SHARED_CHAR_THREATS = ["bidi-override", "null-byte", "control-char", "zero-width"];

var GUARDS = [
  { name: "csv",      file: "guard-csv.js",      profiles: ["strict", "balanced", "permissive", "email-attachment"] },
  { name: "html",     file: "guard-html.js",     profiles: ["strict", "balanced", "permissive"] },
  { name: "svg",      file: "guard-svg.js",      profiles: ["strict", "balanced", "permissive"] },
  { name: "xml",      file: "guard-xml.js",      profiles: ["strict", "balanced", "permissive"] },
  { name: "markdown", file: "guard-markdown.js", profiles: ["strict", "balanced", "permissive"] },
  { name: "json",     file: "guard-json.js",     profiles: ["strict", "balanced", "permissive"] },
];

// The guard-KIND taxonomy (INTEGRATION_FIXTURES.kind / the guard's KIND export)
// is "content" | "entries" | "filename" — not a finding kind, so the scan skips
// these (they are never produced by detect and never reach a content gate).
var NON_FINDING_KINDS = { content: true, entries: true, filename: true };

// Extract every finding kind from a guard source: the token after `kind:` up to
// the first comma, then every quoted string inside it (covers both the literal
// `kind: "x"` and the ternary `kind: c ? "a" : "b"` forms).
function _scanKinds(source) {
  var kinds = {};
  var re = /kind:\s*([^,\n]+)/g;
  var m;
  while ((m = re.exec(source)) !== null) {
    var seg = m[1];
    var qre = /"([a-z][a-z0-9-]*)"/g;
    var q;
    while ((q = qre.exec(seg)) !== null) {
      if (!NON_FINDING_KINDS[q[1]]) kinds[q[1]] = true;
    }
  }
  return Object.keys(kinds);
}

function run() {
  var VALID = { refuse: true, sanitize: true, audit: true };

  GUARDS.forEach(function (g) {
    var mod = require(path.join(LIB, g.file));
    check("[" + g.name + "] exposes dispositionFor test hook",
          typeof mod._gateDispositionForTest === "function");
    if (typeof mod._gateDispositionForTest !== "function") return;

    var kinds = _scanKinds(fs.readFileSync(path.join(LIB, g.file), "utf8"));
    SHARED_CHAR_THREATS.forEach(function (k) { if (kinds.indexOf(k) === -1) kinds.push(k); });

    check("[" + g.name + "] scanned a non-empty finding-kind set", kinds.length > 0);

    var unclassified = [];
    g.profiles.forEach(function (profile) {
      var opts = mod.resolveOpts({ profile: profile });
      kinds.forEach(function (kind) {
        var disp = mod._gateDispositionForTest({ kind: kind, severity: "high" }, opts);
        if (!VALID[disp]) unclassified.push(profile + ":" + kind + "=" + disp);
      });
    });
    check("[" + g.name + "] every finding kind is classified across all profiles" +
          (unclassified.length ? " (UNCLASSIFIED: " + unclassified.slice(0, 8).join(", ") + ")" : ""),
          unclassified.length === 0);
  });
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); console.log("[guard-gate-disposition] OK — " + helpers.getChecks() + " checks passed"); }
  catch (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
}
