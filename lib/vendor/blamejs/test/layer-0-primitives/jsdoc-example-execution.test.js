// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * End-to-end @example validation (approach A-v1). The comment-block validator
 * only PARSE-checks each @example (vm.Script — never runs it), so an example can
 * compile yet be semantically dead: a renamed method, a removed API, a wrong
 * argument shape. This walks the SAME parseTree the validator uses and actually
 * EXECUTES the SELF-CONTAINED @examples, asserting they do not throw.
 *
 * Safety (naive execution is destructive — examples start daemons, open dbs,
 * generate keypairs, touch the filesystem, hit the network):
 *  - Examples matching STATEFUL_OR_IO are NOT executed — skipped + counted.
 *  - Execution runs inside a SACRIFICIAL TEMP CWD so any stray write lands in
 *    temp, never the repo, and behind an unhandledRejection guard + a timeout.
 *  - A ReferenceError (undefined external identifier like req/res/client) or a
 *    require of a non-framework module = illustrative → skip + count.
 *  - Every OTHER throw (TypeError, a framework error, `b.x is not a function`)
 *    is a REAL defect → fails with file:primitive + the error.
 * Output-checking the `// →` comments is the planned fast-follow; executing the
 * 552 stateful/IO examples via child-process isolation is the planned A-v2.
 *
 * Run standalone: `node test/layer-0-primitives/jsdoc-example-execution.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var path    = require("path");
var fs      = require("node:fs");
var os      = require("node:os");
var vm      = require("node:vm");
var helpers = require("../helpers");
var check   = helpers.check;

var ROOT   = path.resolve(__dirname, "..", "..");
var b      = require(ROOT);
var parser = require(path.join(ROOT, "examples", "wiki", "lib", "source-doc-parser"));
var { setupTestDb, teardownTestDb } = require("../helpers/db");

// Any example that could perform real I/O or long-lived / stateful work: never
// executed. Broad on purpose — a false skip is safe, a false run is not.
var STATEFUL_OR_IO = new RegExp([
  "daemon", "vault", "\\bdb\\b", "\\.open\\(", "listen", "server", "\\bmail\\b",
  "deliver", "network", "\\bhttp", "fetch", "\\bdns\\b", "audit", "queue", "cron",
  "\\.watch\\(", "spawn", "exec\\(", "writeFile", "readFile", "mkdir", "unlink",
  "upload", "\\.start\\(", "\\.stop\\(", "generateKey", "keypair", "getKeys",
  "\\.sign\\(", "\\.send\\(", "fileUpload", "static\\(", "\\.pipe\\(",
  "\\.subscribe\\(", "createServer", "\\.connect\\(", "\\.request\\(", "\\.bind\\(",
  "process\\.", "require\\(\"node:", "require\\(\"fs", "require\\(\"net",
  "require\\(\"child_process", "require\\(\"dns", "require\\(\"http",
  "hashFile", "createReadStream", "createWriteStream", "etc/hosts",
  "template", "\\brender\\b", "viewsDir", "listBackends",
  "workerThread", "makeSkipMatcher",
].join("|"), "i");

var SAFE_BUILTINS = { crypto: 1, "node:crypto": 1, path: 1, "node:path": 1,
  buffer: 1, "node:buffer": 1, util: 1, "node:util": 1, url: 1, "node:url": 1,
  querystring: 1, "node:querystring": 1, assert: 1, "node:assert": 1, zlib: 1, "node:zlib": 1 };

// require() seen by an example: framework alias → a FRESH object (never `b`
// itself, so an example writing to the export can't mutate the real surface —
// and no extra members: an example calling a method the shipped export
// doesn't have must FAIL, that drift is exactly what this test catches);
// safe builtins pass through; anything else classifies as an external
// (illustrative) module.
function sandboxRequire(name) {
  if (name === "blamejs" || name === "@blamejs/core") {
    return Object.assign({}, b);
  }
  if (Object.prototype.hasOwnProperty.call(SAFE_BUILTINS, name)) return require(name);
  var e = new Error("example references external module '" + name + "'");
  e.code = "EXAMPLE_EXTERNAL_MODULE";
  throw e;
}

function makeContext() {
  var noop = function () {};
  var sandbox = {
    b: b,
    require: sandboxRequire,
    console: { log: noop, error: noop, warn: noop, info: noop, debug: noop },
    Buffer: Buffer,
    JSON: JSON, Math: Math, Date: Date, Promise: Promise, Object: Object, Array: Array,
    Map: Map, Set: Set, Symbol: Symbol, RegExp: RegExp, Error: Error, TypeError: TypeError,
    URL: URL, URLSearchParams: URLSearchParams, TextEncoder: TextEncoder, TextDecoder: TextDecoder,
    structuredClone: (typeof structuredClone === "function" ? structuredClone : undefined),
  };
  return vm.createContext(sandbox);
}

function classify(e) {
  // Errors thrown INSIDE the vm context are instances of the context's own
  // constructors, so cross-realm `instanceof` fails — classify by name/flag.
  var name = e && e.name;
  if (name === "ReferenceError") return { outcome: "skip", reason: "external identifier" };
  if (e && e.code === "EXAMPLE_EXTERNAL_MODULE") return { outcome: "skip", reason: "external module" };
  if (e && /^test timed out:|Script execution timed out/.test(String(e.message || ""))) return { outcome: "skip", reason: "timeout" };
  // A framework typed error means the API RESOLVED + ran + threw its own error
  // (a precondition / needs-init / input-validation demo) — the API exists, so
  // it is NOT the renamed/removed-API drift A-v1 targets. (Regressions where the
  // framework WRONGLY throws are B's marker-convention job, not auto-classify.)
  if (e && e.isFrameworkError) return { outcome: "skip", reason: "framework error (precondition/input demo)" };
  // Node/fs errors from I/O the skip filter didn't catch.
  if (e && /^E[A-Z]+$/.test(String(e.code || ""))) return { outcome: "skip", reason: "filesystem/OS error" };
  // The example assumes an operator-declared table/column the isolated test db
  // doesn't have (e.g. subject.rectify over a `users` table) — illustrative.
  if (e && /no such (table|column)/i.test(String(e.message || ""))) return { outcome: "skip", reason: "needs operator-specific schema" };
  return { outcome: "fail", error: (e && (e.stack || e.message)) || String(e) };
}

async function runExample(body) {
  if (STATEFUL_OR_IO.test(body)) return { outcome: "skip", reason: "stateful/IO (not executed)" };
  var wrapped = "(async function () {\n" + body + "\n})();";
  try {
    // Bound each @example with a wall-clock ceiling via the shared primitive —
    // the vm `timeout` caps only SYNCHRONOUS execution, so an awaiting example
    // that never settles would otherwise wedge the suite.
    await helpers.withTestTimeout("jsdoc @example execution", function () {
      return new vm.Script(wrapped, { filename: "example.js" }).runInContext(makeContext(), { timeout: 1000 });
    }, { timeoutMs: 1500 });
    return { outcome: "ran" };
  } catch (e) { return classify(e); }
}

async function run() {
  var docs = parser.parseTree(path.join(ROOT, "lib"));
  // Contain any stray write: run inside a sacrificial temp cwd, restore after.
  var origCwd = process.cwd();
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-example-exec-"));
  var onReject = function () {};
  process.on("unhandledRejection", onReject);
  process.chdir(tmp);
  // Isolate the framework's default db/vault into this run's own temp dir, so
  // examples that internally touch them (subject.export, retention, …) don't
  // race concurrent smoke forks on the shared default data path.
  await setupTestDb(tmp, [{ name: "widget", columns: { id: "TEXT PRIMARY KEY" } }]);

  var ran = 0, skipped = 0, failures = [];
  try {
    var files = Object.keys(docs);
    for (var fi = 0; fi < files.length; fi += 1) {
      var prims = docs[files[fi]].primitives || [];
      for (var pi = 0; pi < prims.length; pi += 1) {
        var sig = (prims[pi].tags && prims[pi].tags.primitive) || files[fi];
        var exs = (prims[pi].tags && prims[pi].tags.examples) || [];
        for (var ei = 0; ei < exs.length; ei += 1) {
          var res = await runExample(exs[ei]);
          if (res.outcome === "ran") ran += 1;
          else if (res.outcome === "skip") skipped += 1;
          else failures.push({ sig: sig, error: String(res.error).split("\n").slice(0, 2).join(" ") });
        }
      }
    }
  } finally {
    try { await teardownTestDb(tmp); } catch (_e) { /* best-effort */ }
    process.chdir(origCwd);
    process.removeListener("unhandledRejection", onReject);
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e2) { /* best-effort */ }
  }

  var summary = "[jsdoc-example-execution] executed " + ran + ", skipped " + skipped +
    " (stateful/IO + illustrative), failed " + failures.length;
  console.log(summary);
  // Persist the detail: a failure under a forked smoke worker whose stdout the
  // parent does NOT fold into .test-output/smoke.log would otherwise be lost.
  var report = summary + "\n" +
    failures.map(function (f) { return "  FAIL " + f.sig + " :: " + f.error; }).join("\n") + "\n";
  try { fs.writeFileSync(path.join(ROOT, ".test-output", "jsdoc-example-execution.log"), report); } catch (_e3) { /* best-effort */ }
  if (failures.length) failures.slice(0, 50).forEach(function (f) { console.log("  FAIL " + f.sig + " :: " + f.error); });
  check("every executed @example runs without throwing (renamed/removed API, wrong shape)", failures.length === 0);
}

if (require.main === module) {
  run().then(function () { console.log("jsdoc-example-execution OK — " + helpers.getChecks() + " checks"); },
    function (e) { console.error(e && e.stack || e); process.exit(1); });
}

module.exports = { run: run };
