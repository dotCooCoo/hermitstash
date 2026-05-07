"use strict";
/**
 * Smoke test — orchestrator only.
 *
 * Run: `npm test` (or `node test/smoke.js`)
 *
 * Tests run in dependency order:
 *
 *   Layer 0 — pure primitives                test/00-primitives.js
 *                                            + test/layer-0-primitives/*.test.js
 *   Layer 1 — framework-state primitives     test/10-state.js
 *                                            + test/layer-1-state/*.test.js
 *   Layer 2 — db + framework-schema          test/20-db.js
 *                                            + test/layer-2-db/*.test.js
 *   Layer 3 — chain-writing + cluster-stg    test/30-chain.js
 *                                            + test/layer-3-chain/*.test.js
 *   Layer 4 — consumer modules               test/40-consumers.js
 *                                            + test/layer-4-consumers/*.test.js
 *   Layer 5 — operator-facing integration    test/50-integration.js
 *                                            + test/layer-5-integration/*.test.js
 *
 * Per-file layout (preferred for new tests):
 *   - One file per primitive / module, named `<thing>.test.js`.
 *   - Lives under `test/layer-N-<name>/`.
 *   - Exports `run()` (and optionally `groups[]`).
 *   - Has a CLI entry: `node test/layer-0-primitives/safe-schema.test.js`
 *     runs that file's tests standalone.
 *
 * The legacy single-layer files (00-primitives.js etc.) continue to
 * work alongside the per-file split during the migration window. The
 * orchestrator runs the legacy file FIRST, then walks the per-file
 * directory for the same layer.
 *
 * Shared infrastructure: test/helpers/ — db, mocks, drivers, cluster,
 * http, check. Re-exported from test/helpers/index.js for one-import
 * ergonomics.
 *
 * Per-test timing reported on stdout — drift detection without extra
 * tooling. Format:
 *
 *   <layer>
 *     <test-file>                              (totalMs)
 *
 * Failures throw with attribution: "<layer> / <file>" so the FIRST red
 * light points at the right test file.
 */

var fs   = require("node:fs");
var path = require("node:path");
var { fork } = require("node:child_process");
var os   = require("node:os");
var helpers = require("./helpers");
var b       = helpers.b;

// ---- Persistent output ----
//
// Smoke writes a full copy of every console.log + console.error to
// .test-output/smoke.log so iteration on a failing run doesn't require
// re-running. The .test-output/ dir is gitignored (matches the .*
// dotfile catchall). Operators running locally can ignore the file;
// agents iterating on smoke read it instead of re-running.
var REPO_ROOT = path.resolve(__dirname, "..");
var OUTPUT_DIR = path.join(REPO_ROOT, ".test-output");
try { fs.mkdirSync(OUTPUT_DIR, { recursive: true }); } catch (_e) { /* best-effort */ }
var LOG_PATH = path.join(OUTPUT_DIR, "smoke.log");
// Open the log fd synchronously and write via fs.writeSync — async
// streams don't flush their internal buffer when the process exits via
// uncaughtException, so the persisted log was truncating mid-run.
// Synchronous fd writes hit disk every call; the log is small (~200KB)
// so the perf cost is irrelevant compared to "the failure detail
// actually appears in the log."
try { fs.unlinkSync(LOG_PATH); } catch (_e) { /* fresh start */ }
var _logFd = fs.openSync(LOG_PATH, "w");

function _logWrite(chunk) {
  try {
    var buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
    fs.writeSync(_logFd, buf, 0, buf.length, null);
  } catch (_e) { /* best-effort */ }
}

var _origStdoutWrite = process.stdout.write.bind(process.stdout);
var _origStderrWrite = process.stderr.write.bind(process.stderr);
process.stdout.write = function (chunk, encoding, cb) {
  _logWrite(chunk);
  return _origStdoutWrite(chunk, encoding, cb);
};
process.stderr.write = function (chunk, encoding, cb) {
  _logWrite(chunk);
  return _origStderrWrite(chunk, encoding, cb);
};
process.on("exit", function () {
  try { fs.closeSync(_logFd); } catch (_e) { /* best-effort */ }
});

console.log("blamejs v" + b.version + " — smoke test");
console.log("output: " + LOG_PATH);

// Optional: HS_ONLY=safe-schema.test.js,pagination.test.js — run only
// those per-file tests across all layers (sequential, in arg order).
// Legacy layer files are skipped when HS_ONLY is set so the operator
// gets the iterate-on-one-file flow without re-running the monolith.
var ONLY = (process.env.HS_ONLY || "")
  .split(",").map(function (s) { return s.trim(); }).filter(Boolean);

function _padRight(s, n) {
  if (s.length >= n) return s;
  return s + " ".repeat(n - s.length);
}

function _layerDirFor(layerNum) {
  // Layer 0 → test/layer-0-primitives, Layer 1 → test/layer-1-state, etc.
  var names = ["primitives", "state", "db", "chain", "consumers", "integration"];
  var dir = path.join(__dirname, "layer-" + layerNum + "-" + names[layerNum]);
  if (!fs.existsSync(dir)) return null;
  return dir;
}

// Run a single test file. Backward compat with the legacy
// run() / groups[] export shapes; new files only need run().
async function _runTestModule(modulePath, displayName) {
  var mod = require(modulePath);
  var fileStart = Date.now();
  if (typeof mod.run === "function") {
    try { await mod.run(); }
    catch (err) {
      err.message = displayName + ": " + err.message;
      throw err;
    }
  }
  if (Array.isArray(mod.groups) && mod.groups.length > 0) {
    for (var i = 0; i < mod.groups.length; i++) {
      var group = mod.groups[i];
      var ctx = null;
      try {
        if (typeof group.setup === "function") ctx = await group.setup();
        for (var j = 0; j < group.tests.length; j++) {
          var t = group.tests[j];
          try { await t.run(ctx); }
          catch (err) {
            err.message = displayName + " / " + group.name + " / " + t.name + ": " + err.message;
            throw err;
          }
        }
      } finally {
        if (typeof group.teardown === "function") {
          try { await group.teardown(ctx); }
          catch (_e) { /* teardown errors don't mask test failures */ }
        }
      }
    }
  }
  return Date.now() - fileStart;
}

// Parallel concurrency for layer-0 (set SMOKE_PARALLEL=N to enable;
// default 1 = sequential). Each forked child runs ONE test file in a
// fresh Node process, so module-state isolation is automatic. Layers
// 1-5 stay sequential because they share db / cluster / vault state.
var PARALLEL = parseInt(process.env.SMOKE_PARALLEL || "1", 10);
if (!Number.isFinite(PARALLEL) || PARALLEL < 1) PARALLEL = 1;
// Sanity ceiling — a typo of SMOKE_PARALLEL=1000 should not fork 1000
// children and starve the host. Operator-explicit higher counts up to
// 64 are honoured; the OS scheduler handles oversubscription past
// CPU count without harm (Node fork doesn't crash, just queues).
if (PARALLEL > 64) PARALLEL = 64;                                                // allow:raw-byte-literal — sanity ceiling on parallel children, not bytes
void os;

// _readTimings / _writeTimings — persist per-test durations under
// .test-output/smoke-timings.json so the next run's LPT scheduler can
// place long-tail tests on the first worker. Median of last 5 runs to
// damp out noise from one-off slow runs (CI cold-start, GC pause).
//
// Keyed by `process.platform` so the host (win32/darwin) and the
// Linux container don't pollute each other's medians — fork overhead
// and file I/O speed differ enough that mixing them would mis-rank
// the long-tail tests on whichever platform got fewer recent runs.
// File-write also uses a per-platform staging file so concurrent
// host+container runs don't race on the same JSON.
var TIMINGS_PATH = path.join(__dirname, "..", ".test-output", "smoke-timings.json");
var TIMINGS_PLATFORM_KEY = process.platform;                                     // win32 / linux / darwin
var TIMINGS_KEEP = 5;                                                            // allow:raw-byte-literal — history depth, not bytes

function _readTimings() {
  try {
    var raw = fs.readFileSync(TIMINGS_PATH, "utf8");
    var data = JSON.parse(raw);
    var bucket = (data && data[TIMINGS_PLATFORM_KEY]) || {};
    var medians = {};
    Object.keys(bucket).forEach(function (k) {
      var hist = (bucket[k] && bucket[k].history) || [];
      if (hist.length === 0) return;
      var sorted = hist.slice().sort(function (a, b) { return a - b; });
      medians[k] = sorted[Math.floor(sorted.length / 2)];                        // allow:raw-byte-literal — median index calc
    });
    return medians;
  } catch (_e) {
    return {};
  }
}

function _writeTimings(latest) {
  // Read-merge-write the platform-keyed bucket. Concurrent host +
  // container runs each touch their own bucket; whichever wins the
  // last write loses ONE other run's history (acceptable — TIMINGS_KEEP=5
  // recovers within a couple iterations).
  var existing;
  try { existing = JSON.parse(fs.readFileSync(TIMINGS_PATH, "utf8")); }
  catch (_e) { existing = {}; }
  if (!existing[TIMINGS_PLATFORM_KEY] || typeof existing[TIMINGS_PLATFORM_KEY] !== "object") {
    existing[TIMINGS_PLATFORM_KEY] = {};
  }
  var bucket = existing[TIMINGS_PLATFORM_KEY];
  Object.keys(latest).forEach(function (k) {
    var entry = bucket[k] || { history: [] };
    entry.history.push(latest[k]);
    if (entry.history.length > TIMINGS_KEEP) entry.history = entry.history.slice(-TIMINGS_KEEP);
    bucket[k] = entry;
  });
  try {
    fs.mkdirSync(path.dirname(TIMINGS_PATH), { recursive: true });
    fs.writeFileSync(TIMINGS_PATH, JSON.stringify(existing));
  } catch (_e) { /* read-only fs in CI — silently skip */ }
}

// _runFileForked — fork a Node child to run ONE test file's run().
// The child writes a JSON result line to stdout and exits 0/1. Output
// from the test (helpers.check FAIL messages, etc.) goes to the
// child's stdout/stderr which we pipe to the parent.
function _runFileForked(modulePath, displayName) {
  return new Promise(function (resolve) {
    var fileStart = Date.now();
    var workerScript = path.join(__dirname, "_smoke-worker.js");
    var child = fork(workerScript, [modulePath], {
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      env: Object.assign({}, process.env, { HS_WORKER: "1" }),
    });
    var stdoutBuf = "";
    var stderrBuf = "";
    child.stdout.on("data", function (d) { stdoutBuf += d.toString("utf8"); });
    child.stderr.on("data", function (d) { stderrBuf += d.toString("utf8"); });
    child.on("close", function (code) {
      var ms = Date.now() - fileStart;
      // Last line of stdout is the JSON result line.
      var lines = stdoutBuf.split("\n").filter(Boolean);
      var resultLine = lines[lines.length - 1] || "{}";
      var parsed;
      try { parsed = JSON.parse(resultLine); }
      catch (_e) { parsed = { ok: false, error: "no result line; stderr: " + stderrBuf.slice(0, 500) }; }
      resolve({
        ok:     code === 0 && parsed.ok,
        ms:     ms,
        checks: parsed.checks || 0,
        error:  parsed.error,
        stderr: stderrBuf,
        displayName: displayName,
      });
    });
  });
}

async function _runLayer(layerNum, legacyPath, layerName) {
  // Legacy single-layer file (run only when HS_ONLY isn't set).
  if (ONLY.length === 0 && fs.existsSync(legacyPath)) {
    var legacyMs = await _runTestModule(legacyPath, layerName + " / " + path.basename(legacyPath));
    console.log("  " + _padRight(path.basename(legacyPath), 40) + " (" + legacyMs + "ms)");
  }

  // Per-file tests under layer-N-*/ directory.
  var dir = _layerDirFor(layerNum);
  if (!dir) return;
  var files = fs.readdirSync(dir)
    .filter(function (f) { return f.endsWith(".test.js"); })
    .filter(function (f) { return ONLY.length === 0 || ONLY.indexOf(f) !== -1; })
    .sort();

  // Refuse release-named or slot-named test files — tests must live in
  // per-domain files (one primitive → one test). Catches the antipattern
  // at smoke entry instead of at the codebase-patterns layer-0 gate.
  for (var rfi = 0; rfi < files.length; rfi += 1) {
    var fname = files[rfi];
    if (/^v\d+-\d+-\d+(-|\.)/i.test(fname) || /^slot-\d+/i.test(fname)) {
      throw new Error("smoke: refuse release-named test file '" + fname +
        "' under " + dir + " — split into per-domain test files (one primitive → one test)");
    }
  }

  // Layer 0 is the only layer eligible for parallel — its tests are
  // pure-primitive and don't share db/cluster/vault state. Layers 1+
  // stay sequential.
  if (PARALLEL > 1 && layerNum === 0) {
    // LPT (Longest-Processing-Time-first) scheduling — sort by recorded
    // historical duration descending so the long-tail test starts on
    // worker 1 instead of landing in the last batch. Continuous worker
    // queue: each worker pulls the next file as soon as it finishes.
    // Provably within 4/3 of optimal makespan vs. batched-by-name
    // scheduling that idled workers behind a 19s long-tail test.
    var timings = _readTimings();
    var ordered = files.slice().sort(function (a, b) {
      var ta = timings[a] || Infinity;                                          // unknown → Infinity → schedule early on first run
      var tb = timings[b] || Infinity;
      return tb - ta;
    });
    var cursor = 0;
    var totalChecks = 0;
    var firstFailure = null;
    var resultsByFile = {};
    var newTimings = {};
    async function worker() {
      while (true) {
        if (firstFailure) return;
        var myIdx = cursor++;
        if (myIdx >= ordered.length) return;
        var fname = ordered[myIdx];
        var rv = await _runFileForked(path.join(dir, fname), layerName + " / " + fname);
        resultsByFile[fname] = rv;
        newTimings[fname] = rv.ms;
        if (!rv.ok && !firstFailure) firstFailure = rv;
      }
    }
    var pool = [];
    for (var w = 0; w < PARALLEL; w += 1) pool.push(worker());
    await Promise.all(pool);
    // Print in original sort() order so the per-run output is stable
    // for diff-based comparison (the LPT order is internal scheduling).
    for (var p = 0; p < files.length; p += 1) {
      var rf = resultsByFile[files[p]];
      if (!rf) continue;                                                         // worker pool aborted before this file ran
      totalChecks += rf.checks;
      if (!rf.ok) {
        if (rf.stderr) process.stderr.write(rf.stderr);
        throw new Error(rf.displayName + ": " + (rf.error || "fork failed"));
      }
      console.log("  " + _padRight(files[p], 40) + " (" + rf.ms + "ms)");
    }
    helpers.addExternalChecks(totalChecks);
    _writeTimings(newTimings);
    return;
  }

  for (var seqIdx = 0; seqIdx < files.length; seqIdx++) {
    var fullPath = path.join(dir, files[seqIdx]);
    var ms = await _runTestModule(fullPath, layerName + " / " + files[seqIdx]);
    console.log("  " + _padRight(files[seqIdx], 40) + " (" + ms + "ms)");
  }
}

(async function () {
  var smokeStart = Date.now();
  console.log("Layer 0");
  await _runLayer(0, path.join(__dirname, "00-primitives.js"), "Layer 0");
  console.log("Layer 1");
  await _runLayer(1, path.join(__dirname, "10-state.js"),       "Layer 1");
  console.log("Layer 2");
  await _runLayer(2, path.join(__dirname, "20-db.js"),          "Layer 2");
  console.log("Layer 3");
  await _runLayer(3, path.join(__dirname, "30-chain.js"),       "Layer 3");
  console.log("Layer 4");
  await _runLayer(4, path.join(__dirname, "40-consumers.js"),   "Layer 4");
  console.log("Layer 5");
  await _runLayer(5, path.join(__dirname, "50-integration.js"), "Layer 5");

  console.log("OK — " + helpers.getChecks() + " checks passed (" + (Date.now() - smokeStart) + "ms total)");
})().catch(function (err) {
  console.error("SMOKE TEST FAILED:", err.message);
  console.error(err.stack);
  process.exit(1);
});
