#!/usr/bin/env node
"use strict";
// scripts/validate-source-comment-blocks — framework-level static gate
// that runs the source-driven wiki's @module + @primitive comment-
// block validator from a clean checkout.
//
// Why: the same validator nit class (`@related namespace-not-primitive`,
// missing @primitive blocks, prose-too-short) was rediscovered in CI
// across three consecutive release PRs because the only path that
// surfaced it was the wiki-e2e gate — which requires
// `cd examples/wiki && npm install` and runs ~90s into the smoke
// matrix. Moving the engine into a script that runs in the cheap
// static-gates step (alongside eslint / shellcheck /
// codebase-patterns) catches the same drift pre-push, in <5s.
//
// Pure script — no side effects, no network, no DB. Imports:
//   - examples/wiki/lib/source-comment-block-validator (the engine)
//   - examples/wiki/lib/source-doc-parser              (the parser)
//   - examples/wiki/wiki.config                        (curation pages)
//
// opts-resolver is intentionally NOT imported here. It loads
// @blamejs/core to probe runtime opt allow-lists; the framework's lib/
// itself isn't an npm package at this layer, and the wiki's
// node_modules symlinks aren't guaranteed present in a fresh checkout.
// The opts-undocumented check (#9b) is wiki-e2e exclusive — the
// `examples/wiki/test/validate-source-comment-blocks.js` entry still
// runs it. Every other check fires here.
//
// Exit codes:
//   0 — no findings
//   1 — findings present (CLI prints each finding, file path, and
//       primitive identifier in the same format the wiki-e2e gate
//       emits, so downstream operator muscle memory keeps working)

var path = require("node:path");

var ROOT    = path.resolve(__dirname, "..");
var LIB_DIR = path.join(ROOT, "lib");
var WIKI    = path.join(ROOT, "examples", "wiki");

var engine = require(path.join(WIKI, "lib", "source-comment-block-validator"));
var parser = require(path.join(WIKI, "lib", "source-doc-parser"));

// wiki.config requires site.config → lib/auto-site-entries → source-doc-parser
// — every link is pure (no @blamejs/core, no DB, no vault). When the
// curation can't load for any reason (shouldn't happen on a clean
// checkout), fall back to an empty list — the per-namespace coverage
// check (#8) just goes quiet, the rest of the engine still fires.
var curationPages = [];
try {
  var curation = require(path.join(WIKI, "wiki.config"));
  if (curation && Array.isArray(curation.pages)) curationPages = curation.pages;
} catch (e) {
  console.warn("[validate-source-comment-blocks] wiki.config not loadable: " + (e && e.message) + " — skipping curation cross-check.");
}

function _report(findings) {
  if (findings.length === 0) {
    console.log("[validate-source-comment-blocks] OK - no findings");
    return 0;
  }
  console.log("[validate-source-comment-blocks] " + findings.length + " finding(s):");
  findings.forEach(function (f, i) {
    console.log("  " + (i + 1) + ". [" + f.kind + "] " + f.file + (f.primitive ? " :: " + f.primitive : ""));
    console.log("     " + f.msg);
  });
  return 1;
}

var findings = engine.validate({
  libDir:        LIB_DIR,
  curationPages: curationPages,
  parser:        parser,
  // optsResolver intentionally omitted — see comment block above.
});

process.exit(_report(findings));
