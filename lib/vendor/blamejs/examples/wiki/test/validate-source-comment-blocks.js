"use strict";
// validate-source-comment-blocks — e2e gate for the source-driven
// wiki pipeline (lib/<file>.js -> wiki.config.js -> page-generator.js).
//
// The validation engine itself lives in
// examples/wiki/lib/source-comment-block-validator so the framework's
// static-gates step (scripts/validate-source-comment-blocks.js) can
// invoke the same checks from a clean checkout — no
// `cd examples/wiki && npm install` round-trip.
//
// This file is the wiki-e2e entry: wires the wiki's local
// source-doc-parser + opts-resolver + curation + seeder-index into
// the shared engine, and adds the historical CLI surface
// (--report / --task-list).
//
// Checks the engine performs (every @primitive block):
//
//   1. @primitive carries @signature + prose body + example
//   2. @signature starts with `b.` and matches @primitive's namespace
//   3. @status is stable | experimental | deprecated
//   4. @since looks like semver
//   5. @compliance values are drawn from the posture catalog
//   6. @related references resolve to a documented primitive OR a
//      heading in a hand-authored page seeder
//   7. The first segment of @primitive matches the @module namespace
//   8. Every namespace listed in wiki.config.js has at least one
//      primitive somewhere under lib/
//   9. Every public export in a @module-tagged file's module.exports
//      has a matching @primitive block. Missing blocks become tasks.
//  10. @signature parameter count matches the actual function arity
//  11. @example bodies parse as valid JavaScript
//  12. @example bodies contain no unexecutable placeholders
//  13. proseAfterMultiLine — prose placed AFTER a multi-line tag
//      (gets swallowed by the tag)
//
// Run standalone:
//   node examples/wiki/test/validate-source-comment-blocks.js
//   node examples/wiki/test/validate-source-comment-blocks.js --report
//   node examples/wiki/test/validate-source-comment-blocks.js --task-list
//     (writes wiki-migration-tasks.json + prints task summary; exits 0)

var fs   = require("node:fs");
var path = require("node:path");

var engine       = require("../lib/source-comment-block-validator");
var parser       = require("../lib/source-doc-parser");
var optsResolver = require("../lib/opts-resolver");
var curation     = require("../wiki.config");

var LIB_DIR      = path.join(__dirname, "..", "..", "..", "lib");
var SEEDER_INDEX = path.join(__dirname, "..", "seeders", "prod", "pages", "_index");
var TASK_OUT     = path.join(__dirname, "..", "..", "..", "wiki-migration-tasks.json");

var REPORT_ONLY = process.argv.indexOf("--report") !== -1;
var TASK_LIST   = process.argv.indexOf("--task-list") !== -1;

function validate() {
  return engine.validate({
    libDir:        LIB_DIR,
    curationPages: curation.pages,
    parser:        parser,
    optsResolver:  optsResolver,
    seederIndex:   SEEDER_INDEX,
  });
}

function _emitTaskList(findings) {
  var grouped = {};
  findings.forEach(function (f) {
    var key = f.file + (f.primitive ? ":" + f.primitive : "");
    if (!grouped[key]) grouped[key] = { file: f.file, primitive: f.primitive || null, issues: [] };
    grouped[key].issues.push({ kind: f.kind, msg: f.msg });
  });
  var tasks = Object.keys(grouped).map(function (k, i) {
    return Object.assign({ id: i + 1 }, grouped[k]);
  });
  fs.writeFileSync(TASK_OUT, JSON.stringify({ generatedAt: new Date().toISOString(), taskCount: tasks.length, tasks: tasks }, null, 2));
  console.log("[validate-source-comment-blocks] wrote " + tasks.length + " task(s) to " + path.relative(process.cwd(), TASK_OUT));
  // Group summary by kind for the operator.
  var byKind = {};
  findings.forEach(function (f) { byKind[f.kind] = (byKind[f.kind] || 0) + 1; });
  console.log("by kind:");
  Object.keys(byKind).sort().forEach(function (k) { console.log("  " + k.padEnd(22) + " " + byKind[k]); });
}

function _report(findings) {
  if (TASK_LIST) {
    _emitTaskList(findings);
    return 0;
  }
  if (findings.length === 0) {
    console.log("[validate-source-comment-blocks] OK - no findings");
    return 0;
  }
  console.log("[validate-source-comment-blocks] " + findings.length + " finding(s):");
  findings.forEach(function (f, i) {
    console.log("  " + (i + 1) + ". [" + f.kind + "] " + f.file + (f.primitive ? " :: " + f.primitive : ""));
    console.log("     " + f.msg);
  });
  return REPORT_ONLY ? 0 : 1;
}

if (require.main === module) {
  process.exit(_report(validate()));
}

module.exports = { validate: validate };
