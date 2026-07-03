// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Source @module / @primitive comment-block gate.
 *
 * Same engine that runs in CI's `Wiki @module / @primitive comment-
 * block convention` job (`scripts/validate-source-comment-blocks.js`),
 * but wired into smoke as a Layer 0 check so the validator fires on
 * every `node test/smoke.js` invocation — not just when someone
 * remembers to invoke the standalone script.
 *
 * Catches the class of finding Codex / CI flagged on PRs #50 / #51 /
 * #52 / #53 / #54 (missing `@primitive` block, `@related` namespace
 * vs primitive reference, prose-too-short, `@example` parse error).
 */

var path     = require("node:path");
var validator = require(path.join(__dirname, "..", "..", "examples", "wiki", "lib",
                                  "source-comment-block-validator.js"));
var parser    = require(path.join(__dirname, "..", "..", "examples", "wiki", "lib",
                                  "source-doc-parser"));
var helpers  = require("../helpers");
var check    = helpers.check;

// Local opts-resolver — mirrors examples/wiki/lib/opts-resolver.js but
// resolves `b` through the in-tree framework instead of the wiki's npm
// `@blamejs/core` symlink. Wires the opts-undocumented check into the
// framework smoke gate so the class CI's wiki-e2e was the only catcher
// of (PR #58 v0.9.31 missed @opts blocks) fires pre-push.
function _buildLocalOptsResolver() {
  var b;
  try { b = require("../.."); }
  catch (_e) { return null; }
  function _resolveFn(signature) {
    var m = String(signature).match(/^\s*(?:<code>\s*)?b\.([a-zA-Z0-9_.]+)\s*\(/);
    if (!m) return null;
    var parts = m[1].split(".");
    var cur = b;
    for (var i = 0; i < parts.length; i += 1) {
      if (cur === null || cur === undefined) return null;
      cur = cur[parts[i]];
    }
    return typeof cur === "function" ? cur : null;
  }
  function _probe(fn) {
    if (typeof fn !== "function") return { ok: false, reason: "not-a-function" };
    var probeKey = "__opts_smoke_probe_" + Date.now() + "_" + Math.random().toString(36).slice(2);     // allow:math-random-noncrypto-jitter-sampling — probe-key uniqueness only
    var probeOpts = {}; probeOpts[probeKey] = true;
    var caught = null;
    try {
      var rv = fn(probeOpts);
      if (rv && typeof rv.then === "function") {
        rv.catch(function () { /* async validation; probe doesn't surface */ });
        return { ok: false, reason: "async-only-validation" };
      }
    } catch (e) { caught = e; }
    if (!caught) return { ok: false, reason: "no-throw" };
    var msg = caught.message || String(caught);
    var match = msg.match(/Allowed(?:\s+keys)?:\s*([^.]*)/i);
    if (!match) return { ok: false, reason: "no-allow-list-in-error" };
    var keys = match[1].split(",")
      .map(function (s) { return s.trim().replace(/[`'"]/g, ""); })
      .filter(Boolean);
    return { ok: true, allowed: keys };
  }
  return {
    resolve: function (signature) {
      var fn = _resolveFn(signature);
      if (!fn) return { ok: false, reason: "lib-fn-not-resolved" };
      return _probe(fn);
    },
  };
}

var optsResolver = _buildLocalOptsResolver();

async function run() {
  var libDir = path.join(__dirname, "..", "..", "lib");
  var findings = validator.validate({
    libDir:       libDir,
    parser:       parser,
    curationPages: [],          // wiki-only concept; framework smoke doesn't seed pages
    optsResolver: optsResolver, // enables the opts-undocumented probe in smoke
  });

  if (findings.length > 0) {
    // Surface every finding so smoke output names exactly what to fix.
    for (var i = 0; i < findings.length; i += 1) {
      var f = findings[i];
      var label = "source-comment-blocks: " +
                  (f.kind || "finding") + " — " +
                  (f.file ? f.file : "<unknown file>") +
                  (f.primitive ? " :: " + f.primitive : "") +
                  ": " + (f.msg || "");
      check(label, false);
    }
    return;
  }
  check("source-comment-blocks: validator clean (no findings)", true);
}

module.exports = { run: run };
if (require.main === module) {
  run().then(function () { console.log("OK"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
