#!/usr/bin/env node
"use strict";
/**
 * Branch-coverage union across every suite that executes this codebase.
 *
 * The point is the union, not any single suite's number. Unit tests reach
 * helpers that no request touches; the end-to-end suite reaches request paths,
 * worker threads and the WebSocket stream that no unit test constructs. Read
 * apart they each look thin and neither tells you what is actually unexercised.
 *
 * Every run writes raw V8 coverage into one directory via NODE_V8_COVERAGE,
 * which accumulates across processes — including servers this process never
 * started, since the variable is inherited. c8 then reports over the union.
 *
 *   node scripts/coverage.js                  # every suite, then the report
 *   node scripts/coverage.js --no-e2e         # skip the slow one
 *   node scripts/coverage.js --report-only    # re-report existing raw output
 *   node scripts/coverage.js --check          # exit non-zero below THRESHOLDS
 *
 * c8's CLI cannot run here — its bundled yargs fails to load under Node 26
 * ("require is not defined in ES module scope"), which is why the tests/
 * package script that shells out to `npx c8` has never produced a number. Its
 * report engine is fine, so this drives that directly and skips the CLI.
 */
var cp = require("node:child_process");
var fs = require("node:fs");
var path = require("node:path");

var REPO = path.resolve(__dirname, "..");
var SYNC = path.resolve(REPO, "..", "hermitstash-sync");
var COV = path.join(REPO, ".coverage");
var RAW = path.join(COV, "raw");

// Measured floors, rounded down to a whole percent, not opinions about what is
// enough. They exist to catch a regression, so raise them as gaps close and
// never lower one to make a run pass.
//
// Measured on Windows, where the end-to-end suite's servers contribute nothing
// (see serverCoverageCaptured below), so a POSIX run should clear these
// comfortably. That asymmetry is the reason for rounding down rather than
// pinning to the exact figure.
var THRESHOLDS = { lines: 70, branches: 69, functions: 70, statements: 70 };

// What the union is measured against: code this project owns and ships.
// Vendored trees are upstream's to test, the test files are the instrument
// rather than the subject, and the browser bundles under public/js are copies
// of the vendored builds.
//
// `all: true` counts files no suite loaded, which is the point — an untouched
// file is exactly the gap worth seeing. It also means anything on disk under
// src counts, so the gitignored working directories are named here too: a
// throwaway probe left in .test-output would otherwise read as uncovered
// production code and move the number from one machine to the next.
var EXCLUDE = [
  "lib/vendor/**", "tests/**", "public/js/**", "template/**", "deploy/**",
  "scripts/**", "coverage/**", ".coverage/**", "node_modules/**",
  ".test-output/**", ".vendor-blamejs.tmp/**", ".scratch/**",
  "**/*.test.js", "**/*.min.js",
];

// Clearing the raw directory is not best-effort. A leftover file from an
// earlier run merges into this one, and it merges in the flattering direction:
// coverage only ever adds. The union would read higher than the code earns and
// --check would pass over a real regression. Dropbox and virus scanners hold
// locks on this tree often enough that the failure is worth refusing on.
function clearRaw() {
  try { fs.rmSync(RAW, { recursive: true, force: true }); } catch (_e) { /* checked below */ }
  var left = [];
  try { left = fs.readdirSync(RAW); } catch (_e) { return; } // gone, as intended
  if (left.length) {
    console.error("could not clear " + RAW + " — " + left.length + " file(s) remain.");
    console.error("Stale coverage would merge into this run and read higher than it should.");
    console.error("Close whatever holds them (Dropbox sync, a virus scanner, an editor) and retry.");
    process.exit(2);
  }
}

// NODE_ENV is deliberately left as the caller set it. The package scripts pass
// NODE_ENV=test, but nothing in this codebase branches on that value — the four
// places that read it all test for "production" — so passing it would change no
// code path here, and setting it in new tooling invites the test-only branches
// this project does not allow.
function run(label, cmd, args, opts) {
  process.stdout.write("  " + label + " … ");
  var started = Date.now();
  try {
    cp.execFileSync(cmd, args, Object.assign({
      cwd: REPO,
      stdio: ["ignore", "pipe", "pipe"],
      env: Object.assign({}, process.env, { NODE_V8_COVERAGE: RAW }),
    }, opts || {}));
    console.log("ok (" + Math.round((Date.now() - started) / 1000) + "s)");
    return true;
  } catch (e) {
    // A failing suite still leaves its coverage behind, and a partial union is
    // more useful than none — report the failure and keep going, so one broken
    // suite does not hide the numbers for the rest.
    console.log("FAILED (" + Math.round((Date.now() - started) / 1000) + "s)");
    var out = ((e.stdout || "") + (e.stderr || "")).toString().trim().split("\n").slice(-8);
    out.forEach(function (l) { console.log("      " + l); });
    return false;
  }
}

function suites(opts) {
  var ok = true;
  // performance is in the union because it executes production code like any
  // other suite — whatever it reaches counts, whether or not its assertions are
  // about timing. Leaving it out reported its paths as unreached.
  ["unit", "security", "integration", "performance"].forEach(function (s) {
    ok = run(s, "node", ["--test", "--test-reporter=dot", "tests/" + s + "/*.test.js"]) && ok;
  });

  if (opts.e2e) {
    if (!fs.existsSync(SYNC)) {
      console.log("  e2e … skipped (no sibling hermitstash-sync checkout)");
    } else {
      // Snapshot taken here so the capture check below can tell this run's
      // output from the suites that already wrote into the same directory.
      opts.rawBeforeE2e = listRaw();
      // The runner boots this server as a child process. NODE_V8_COVERAGE is
      // inherited, so the server's own execution lands in the same directory —
      // which is the coverage that matters here, and the reason e2e is in the
      // union at all rather than measured on its own.
      ok = run("e2e", "node", ["tests/run-all.js"], {
        cwd: SYNC,
        env: Object.assign({}, process.env, {
          NODE_V8_COVERAGE: RAW,
          HERMITSTASH_SERVER_DIR: REPO,
        }),
      }) && ok;
    }
  } else {
    console.log("  e2e … skipped (--no-e2e)");
  }
  return ok;
}

/**
 * Did the servers the end-to-end suite booted actually record anything?
 *
 * V8 writes its coverage when a process exits cleanly. The suite stops each
 * server with SIGTERM, which the server handles — on a POSIX host. Windows has
 * no signals, so Node turns that call into an unconditional termination, the
 * shutdown handler never runs, and everything that server executed is dropped.
 *
 * The failure is silent and it flatters the result: the suite passes, the run
 * looks complete, and the percentage simply omits every request path only the
 * end-to-end suite reaches. Checking for a file the server must have loaded is
 * what tells the difference between "these branches are untested" and "these
 * branches were tested by a process whose output was thrown away".
 *
 * Only files written DURING the end-to-end run count. Everything shares one
 * output directory, and an integration test that boots a server leaves behind a
 * file naming server-main.js too — reading the whole directory would let that
 * answer for the end-to-end suite and suppress the very warning this exists to
 * raise.
 */
function listRaw() {
  try { return fs.readdirSync(RAW); } catch (_e) { return []; }
}

function serverCoverageCaptured(before) {
  var seen = new Set(before);
  return listRaw().some(function (f) {
    if (!/\.json$/.test(f) || seen.has(f)) return false;
    try {
      return fs.readFileSync(path.join(RAW, f), "utf8").indexOf("server-main.js") !== -1;
    } catch (_e) { return false; }
  });
}

async function report(check) {
  var Report = require(path.join(REPO, "tests", "node_modules", "c8", "lib", "report.js"));
  var reporters = ["text-summary", "html", "json-summary"];
  var r = new Report({
    include: [],
    exclude: EXCLUDE,
    extension: [".js"],
    reporter: reporters,
    reportsDirectory: path.join(COV, "report"),
    tempDirectory: RAW,
    src: [REPO],
    all: true,            // count files no suite loaded — an untouched file is the gap
    excludeNodeModules: true,
    omitRelative: false,
    resolve: "",
    wrapperLength: 0,
    watermarks: {},
  });
  await r.run();

  var summaryPath = path.join(COV, "report", "coverage-summary.json");
  if (!fs.existsSync(summaryPath)) {
    console.log("\n  no summary written — nothing to check against");
    return 0;
  }
  var total = JSON.parse(fs.readFileSync(summaryPath, "utf8")).total;
  console.log("\n  union: "
    + ["lines", "branches", "functions", "statements"].map(function (k) {
      return k + " " + total[k].pct + "%";
    }).join("  ·  "));
  console.log("  html: " + path.join(COV, "report", "index.html"));

  if (!check) return 0;
  var failed = Object.keys(THRESHOLDS).filter(function (k) {
    return total[k].pct < THRESHOLDS[k];
  });
  failed.forEach(function (k) {
    console.log("  FAIL " + k + " " + total[k].pct + "% < " + THRESHOLDS[k] + "%");
  });
  return failed.length ? 1 : 0;
}

async function main() {
  var argv = process.argv.slice(2);
  var reportOnly = argv.indexOf("--report-only") !== -1;
  var check = argv.indexOf("--check") !== -1;

  var ranE2e = argv.indexOf("--no-e2e") === -1;
  var suitesPassed = true;
  if (!reportOnly) {
    clearRaw();
    fs.mkdirSync(RAW, { recursive: true });
    console.log("coverage — running suites into one V8 output directory");
    var runOpts = { e2e: ranE2e, rawBeforeE2e: null };
    suitesPassed = suites(runOpts);

    if (ranE2e && runOpts.rawBeforeE2e && !serverCoverageCaptured(runOpts.rawBeforeE2e)) {
      console.log("\n  WARNING — the end-to-end suite ran but no server process recorded coverage.");
      console.log("  Every request path only that suite reaches is missing from the numbers below,");
      console.log("  so treat them as a floor rather than a measurement.");
      if (process.platform === "win32") {
        console.log("  Cause on this host: the suite stops each server with SIGTERM, and Windows has");
        console.log("  no signals — Node turns that into an unconditional kill, so V8 never writes.");
        console.log("  Run the union on Linux (or in CI) for a number that includes the server.");
      }
    }
  }

  if (!fs.existsSync(RAW) || fs.readdirSync(RAW).length === 0) {
    console.log("\n  no raw coverage in " + RAW + " — run without --report-only first");
    process.exit(2);
  }

  // Report first, then fail. A failing suite still leaves useful coverage, and
  // the numbers are worth seeing either way — but the run must not exit 0 on
  // the strength of a threshold when a suite underneath it was red. Coverage
  // measured from a failing run describes what ran, not what works.
  var thresholdCode = await report(check);
  if (!suitesPassed) {
    console.log("\n  FAIL — a suite failed; the coverage above describes a red run.");
    process.exit(1);
  }
  process.exit(thresholdCode);
}

main().catch(function (e) {
  console.error("coverage failed: " + (e && e.stack ? e.stack : e));
  process.exit(2);
});
