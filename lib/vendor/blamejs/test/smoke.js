// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
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

async function _runModuleBody(mod, displayName) {
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
}

// Run a single test file. Backward compat with the legacy
// run() / groups[] export shapes; new files only need run().
//
// The sequential layers (1-5) run in-process, so unlike the forked
// layer-0 children they have no per-fork watchdog. A hung async op here
// (a blocking native call starved on the libuv threadpool, a leaked
// handle, an awaited promise that never settles) would otherwise ride
// to the CI job's wall-clock limit as an unattributable multi-hour
// hang. This in-process watchdog races the file body against the same
// FILE_TIMEOUT_MS budget: the main loop stays responsive while a
// threadpool thread is stuck, so the timer fires, names the file, and
// fails fast and diagnosably.
async function _runTestModule(modulePath, displayName) {
  var mod = require(modulePath);
  var fileStart = Date.now();
  var watchdog = null;
  var timed = new Promise(function (_resolve, reject) {
    watchdog = setTimeout(function () {
      reject(new Error(displayName + ": sequential-layer watchdog — exceeded " +
        FILE_TIMEOUT_MS + "ms with no completion (likely a hung async op: " +
        "libuv-threadpool starvation, a leaked handle, or a blocking native call)"));
    }, FILE_TIMEOUT_MS);
    if (typeof watchdog.unref === "function") watchdog.unref();
  });
  try {
    await Promise.race([_runModuleBody(mod, displayName), timed]);
  } finally {
    if (watchdog !== null) clearTimeout(watchdog);
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

// Per-file watchdog budget. A forked child that never exits (leaked
// timer / socket / fs.watch handle — more common on macOS) would
// otherwise hang the whole run until the CI job's wall-clock limit.
// Past this budget the child is SIGKILLed and the file reported as a
// failure that NAMES the file, turning an unattributable multi-hour
// hang into a fast, diagnosable error. Generous (the full host suite
// runs in ~140s); override with SMOKE_FILE_TIMEOUT_MS.
var FILE_TIMEOUT_MS = parseInt(process.env.SMOKE_FILE_TIMEOUT_MS || "300000", 10);
if (!Number.isFinite(FILE_TIMEOUT_MS) || FILE_TIMEOUT_MS < 1000) FILE_TIMEOUT_MS = 300000;

// Solo files (SMOKE_RUN_SOLO — CPU-bound scans that fan out across the whole
// box, e.g. the duplicate-block pattern catalog) get a MULTIPLIED budget. They
// run ALONE, so a generous timeout can't mask a parallel-contention hang, and
// their cost scales with the lib/ + test/ corpus, which grows every release —
// a single fixed budget needs bumping each time the corpus crosses it on a
// low-core runner (macos-latest = 3 cores), the recurring release friction
// this removes. Multiplying the base budget decouples solo headroom from the
// pool budget so the treadmill stops. A genuine solo-file hang is still caught.
var SOLO_TIMEOUT_MULT = parseInt(process.env.SMOKE_SOLO_TIMEOUT_MULT || "4", 10);
if (!Number.isFinite(SOLO_TIMEOUT_MULT) || SOLO_TIMEOUT_MULT < 1) SOLO_TIMEOUT_MULT = 4;
var SOLO_TIMEOUT_MS = FILE_TIMEOUT_MS * SOLO_TIMEOUT_MULT;

// A forked file that fails at the PROCESS level — a spawn error (EAGAIN /
// EMFILE under load) or a non-zero exit AFTER its assertions already passed (a
// leaked-handle teardown, far more common on a resource-starved macos runner)
// — is retried ONCE. A CLEAN assertion failure (the test ran and reported
// ok:false) and a watchdog timeout are NOT retried: those are deterministic /
// already-budgeted, so retrying would only mask a real failure or burn another
// full budget. The retry recovers the transient-runner case without hiding a
// real one (a deterministic failure fails again).
var FORK_RETRIES = parseInt(process.env.SMOKE_FORK_RETRIES || "1", 10);
if (!Number.isFinite(FORK_RETRIES) || FORK_RETRIES < 0) FORK_RETRIES = 1;

// Opt-in leaked-handle audit (SMOKE_AUDIT_HANDLES=1). The worker always
// computes the per-file leak set (cheap); this gate only controls REPORTING,
// because the snapshot-diff over-reports async-closing handles as false
// positives. Turn it on to triage the real-leak population for a cleanup pass.
var AUDIT_HANDLES = !!process.env.SMOKE_AUDIT_HANDLES;

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
function _runFileForked(modulePath, displayName, timeoutMs) {
  var budget = (typeof timeoutMs === "number" && timeoutMs > 0) ? timeoutMs : FILE_TIMEOUT_MS;
  return new Promise(function (resolve) {
    var fileStart = Date.now();
    var workerScript = path.join(__dirname, "_smoke-worker.js");
    var child = fork(workerScript, [modulePath], {
      stdio: ["ignore", "pipe", "pipe", "ipc"],
      env: Object.assign({}, process.env, { HS_WORKER: "1" }),
      execArgv: ["--max-old-space-size=8192"],
    });
    var stdoutBuf = "";
    var stderrBuf = "";
    // Single-resolve guard: close / error / watchdog can all fire; the
    // first one wins and cancels the watchdog so a normal exit never
    // trips it and a kill never double-resolves.
    var settled = false;
    function settle(result) {
      if (settled) return;
      settled = true;
      clearTimeout(watchdog);
      resolve(result);
    }
    var watchdog = setTimeout(function () {
      // Child overran the budget with no exit — reap it and report a
      // failure that names the file + the most likely cause. NOT retriable:
      // a timeout is already-budgeted, so a retry would just burn another
      // full budget.
      try { child.kill("SIGKILL"); } catch (_e) { /* already gone */ }
      settle({
        ok:     false,
        ms:     Date.now() - fileStart,
        checks: 0,
        error:  "watchdog: '" + displayName + "' exceeded " + budget +
                "ms with no exit — likely a leaked handle (timer / socket / fs.watch). " +
                "Last stderr: " + (stderrBuf.slice(-500) || "(none)"),
        stderr: stderrBuf,
        displayName: displayName,
        retriable: false,
      });
    }, budget);
    if (typeof watchdog.unref === "function") watchdog.unref();
    child.stdout.on("data", function (d) { stdoutBuf += d.toString("utf8"); });
    child.stderr.on("data", function (d) { stderrBuf += d.toString("utf8"); });
    child.on("error", function (e) {
      // fork() itself failed (ENOENT / EMFILE / spawn error) — without
      // this handler the Promise would never resolve and hang the run. A
      // spawn failure under load (EAGAIN / EMFILE) is transient → retriable.
      settle({
        ok:     false,
        ms:     Date.now() - fileStart,
        checks: 0,
        error:  displayName + ": fork error: " + ((e && e.message) || String(e)),
        stderr: stderrBuf,
        displayName: displayName,
        retriable: true,
      });
    });
    child.on("close", function (code) {
      var ms = Date.now() - fileStart;
      // Last line of stdout is the JSON result line.
      var lines = stdoutBuf.split("\n").filter(Boolean);
      var resultLine = lines[lines.length - 1] || "{}";
      var parsed;
      try { parsed = JSON.parse(resultLine); }
      catch (_e) { parsed = { ok: false, error: "no result line; stderr: " + stderrBuf.slice(0, 500) }; }
      // A non-zero exit AFTER the assertions passed (parsed.ok === true) is a
      // process-level teardown failure — a leaked handle that delays / faults
      // exit, common on a resource-starved runner — and is retriable. A clean
      // assertion failure (parsed.ok === false) is deterministic, NOT retriable.
      // Retriable process-level transients: a non-zero exit after the
      // assertions passed (a leaked handle faulting exit) OR a late async error
      // the worker attributed (parsed.lateError). Both differ from a clean
      // assertion failure (parsed.ok === false WITHOUT lateError), which is
      // deterministic and NOT retried.
      var processFailedAfterPass = code !== 0 && parsed.ok === true;
      var lateError = parsed.lateError === true;
      settle({
        ok:     code === 0 && parsed.ok,
        ms:     ms,
        checks: parsed.checks || 0,
        error:  parsed.error || (processFailedAfterPass
          ? (displayName + ": process exited non-zero (" + code + ") after assertions passed " +
             "— likely a leaked handle on a slow runner. Last stderr: " + (stderrBuf.slice(-300) || "(none)"))
          : undefined),
        stderr: stderrBuf,
        displayName: displayName,
        retriable: processFailedAfterPass || lateError,
        leaks:  Array.isArray(parsed.leaks) ? parsed.leaks : [],
      });
    });
  });
}

// Run a forked file, retrying ONCE (FORK_RETRIES) on a PROCESS-level transient
// (spawn error / non-zero-exit-after-pass) but never on a clean assertion
// failure or a watchdog timeout — recovers a starved-runner flake without
// masking a real failure (a deterministic failure fails again on the retry).
async function _runFileForkedRetrying(modulePath, displayName, timeoutMs) {
  var rv = await _runFileForked(modulePath, displayName, timeoutMs);
  var attempts = 0;
  while (!rv.ok && rv.retriable && attempts < FORK_RETRIES) {
    attempts += 1;
    console.log("  [retry " + attempts + "/" + FORK_RETRIES + "] " + displayName +
      " — process-level transient (" + (rv.error || "fork failed").slice(0, 120) + ")");
    rv = await _runFileForked(modulePath, displayName, timeoutMs);
  }
  return rv;
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
    .filter(function (f) {
      // STANDALONE_ONLY marker — test file opts out of default smoke
      // by including the literal token in its top-of-file comment.
      // Operator override: HS_ONLY=<name>.test.js still includes it.
      // Used for heavy fault-injection drills that spin worker threads,
      // generate real keypairs, etc.
      if (ONLY.length > 0) return true;
      try {
        var head = fs.readFileSync(path.join(dir, f), "utf8").slice(0, 2048);
        return head.indexOf("STANDALONE_ONLY") === -1;
      } catch (_e) { return true; }
    })
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
    var totalChecks = 0;
    var firstFailure = null;
    var resultsByFile = {};
    var newTimings = {};

    // A file that declares the SMOKE_RUN_SOLO marker (a CPU-bound test
    // that itself fans out across worker_threads — e.g. the pattern-
    // catalog duplicate-scan) runs ALONE with the whole box, NOT in the
    // parallel pool. On a low-core runner (macos-latest = 3 cores) its
    // internal workers plus the sibling forks oversubscribe the CPU and
    // the scan overruns its per-file budget; given the whole box it
    // finishes in its normal time. Marker-based, not timing-based, so it
    // works on a fresh CI runner that has no persisted timings yet.
    var soloFiles = [];
    var poolFiles = [];
    for (var pf = 0; pf < files.length; pf += 1) {
      var solo = false;
      try {
        solo = fs.readFileSync(path.join(dir, files[pf]), "utf8")
          .slice(0, 2048).indexOf("SMOKE_RUN_SOLO") !== -1;
      } catch (_e) { solo = false; }
      (solo ? soloFiles : poolFiles).push(files[pf]);
    }

    // Solo phase — heavy files one at a time, each with the full box and the
    // multiplied solo budget (their cost scales with the growing corpus).
    for (var si = 0; si < soloFiles.length && !firstFailure; si += 1) {
      var sName = soloFiles[si];
      var srv = await _runFileForkedRetrying(path.join(dir, sName), layerName + " / " + sName, SOLO_TIMEOUT_MS);
      resultsByFile[sName] = srv;
      newTimings[sName] = srv.ms;
      if (!srv.ok && !firstFailure) firstFailure = srv;
    }

    // Pool phase — light remainder, LPT (Longest-Processing-Time-first)
    // scheduled: sort by recorded historical duration descending so the
    // long-tail file starts on worker 1 instead of landing in the last
    // batch (within 4/3 of optimal makespan). Continuous queue: each
    // worker pulls the next file as soon as it finishes.
    var timings = _readTimings();
    var ordered = poolFiles.slice().sort(function (a, b) {
      var ta = timings[a] || Infinity;                                          // unknown → Infinity → schedule early on first run
      var tb = timings[b] || Infinity;
      return tb - ta;
    });
    var cursor = 0;
    async function worker() {
      while (true) {
        if (firstFailure) return;
        var myIdx = cursor++;
        if (myIdx >= ordered.length) return;
        var fname = ordered[myIdx];
        var rv = await _runFileForkedRetrying(path.join(dir, fname), layerName + " / " + fname);
        resultsByFile[fname] = rv;
        newTimings[fname] = rv.ms;
        if (!rv.ok && !firstFailure) firstFailure = rv;
      }
    }
    if (!firstFailure) {
      var pool = [];
      for (var w = 0; w < PARALLEL; w += 1) pool.push(worker());
      await Promise.all(pool);
    }

    // Print in original sort() order so the per-run output is stable
    // for diff-based comparison (the solo/LPT order is internal scheduling).
    var leakReport = [];
    for (var p = 0; p < files.length; p += 1) {
      var rf = resultsByFile[files[p]];
      if (!rf) continue;                                                         // pool aborted before this file ran
      totalChecks += rf.checks;
      if (!rf.ok) {
        if (rf.stderr) process.stderr.write(rf.stderr);
        throw new Error(rf.displayName + ": " + (rf.error || "fork failed"));
      }
      console.log("  " + _padRight(files[p], 40) + " (" + rf.ms + "ms)" +
        (AUDIT_HANDLES && rf.leaks && rf.leaks.length ? "  [leaked: " + rf.leaks.join(", ") + "]" : ""));
      if (rf.leaks && rf.leaks.length) leakReport.push(files[p] + " :: " + rf.leaks.join(", "));
    }
    // Handle-leak population — opt-in diagnostic (SMOKE_AUDIT_HANDLES=1). A
    // test that leaks a timer / socket / server / worker is the same root that
    // flakes a slow runner (delay) or throws after pass (fork-fail). Off by
    // default because the snapshot-diff over-reports async-CLOSING handles (a
    // server whose close() callback fired but whose handle lingers a tick past
    // the grace window) as false positives; turn it on to triage real leaks.
    if (AUDIT_HANDLES && leakReport.length) {
      console.log("");
      console.log("  ⚠ " + leakReport.length + " layer-0 file(s) held a handle past run() " +
        "(SMOKE_AUDIT_HANDLES — triage: real leak vs async-close-in-flight):");
      for (var lr = 0; lr < leakReport.length; lr += 1) console.log("      " + leakReport[lr]);
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

// Release-notes rollup gate. The current minor stays as per-patch
// `release-notes/v<X>.<Y>.<Z>.json` files (so the active line edits
// one small JSON per release), every PREVIOUS minor collapses to a
// single `release-notes/v<X>.<Y>.x.json`. The check is non-mutating —
// it exits non-zero if any non-current minor still has per-patch
// files, telling the operator to run `--prune` between releases. It
// stays OUT of the release flow itself so consolidation never shifts
// the tarball's file set after the SHA-256 / SHA3-512 / ML-DSA
// digests are computed.
function _checkReleaseNotesRollup() {
  var cp = require("node:child_process");
  var r = cp.spawnSync(
    process.execPath,
    [path.join(REPO_ROOT, "scripts", "consolidate-release-notes.js"), "--check"],
    { cwd: REPO_ROOT, stdio: ["ignore", "inherit", "inherit"] }
  );
  if (r.status !== 0) {
    throw new Error(
      "release-notes rollup needed — run `node scripts/consolidate-release-notes.js --prune` " +
      "to roll up non-current minor lines into v<minor>.x.json (do this BEFORE cutting a release branch)"
    );
  }
}

// CHANGELOG.md is a derived artifact rebuilt from `release-notes/`.
// This gate runs the generator's `--check` mode — in-memory rebuild
// + diff against on-disk — and fails fast when an operator added /
// edited a release-notes JSON without running `--rebuild`. Same
// non-mutating discipline as the rollup gate: smoke never writes to
// the working tree.
function _checkChangelogInSync() {
  var cp = require("node:child_process");
  var r = cp.spawnSync(
    process.execPath,
    [path.join(REPO_ROOT, "scripts", "generate-changelog-entry.js"), "--check"],
    { cwd: REPO_ROOT, stdio: ["ignore", "inherit", "inherit"] }
  );
  if (r.status !== 0) {
    throw new Error(
      "CHANGELOG.md drift — run `node scripts/generate-changelog-entry.js --rebuild` " +
      "to regenerate from release-notes/, then commit both files"
    );
  }
}

(async function () {
  var smokeStart = Date.now();
  console.log("Static gates");
  _checkReleaseNotesRollup();
  console.log("  " + _padRight("release-notes-rollup", 40) + " (ok)");
  _checkChangelogInSync();
  console.log("  " + _padRight("changelog-in-sync", 40) + " (ok)");
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

  // Deterministic exit on success. The .catch() below exits 1 on
  // failure; the success path historically fell through and relied on
  // the event loop draining on its own. A lingering handle (a forked-
  // child stdio pipe, a Layer-5 integration server whose socket did not
  // fully close, an unref-missed timer) then keeps the process alive
  // after the suite finished, burning the CI job's timeout budget until
  // the runner cancels it — observed on the slow macos-latest runner
  // (OK printed, ~3.5 min idle, job-timeout cancel). Reap it here: if
  // anything still holds the loop open, name the handle kinds so a real
  // resource leak surfaces in the log rather than being silently masked,
  // then exit 0.
  var _stdio = [process.stdout, process.stderr, process.stdin];
  var _lingering = (typeof process._getActiveHandles === "function"
    ? process._getActiveHandles() : []).filter(function (h) { return _stdio.indexOf(h) === -1; });
  if (_lingering.length > 0) {
    var _kinds = {};
    _lingering.forEach(function (h) {
      var name = (h && h.constructor && h.constructor.name) || typeof h;
      _kinds[name] = (_kinds[name] || 0) + 1;
    });
    console.error("smoke: " + _lingering.length + " handle(s) still open after pass — forcing exit. kinds: " +
      Object.keys(_kinds).map(function (k) { return k + "x" + _kinds[k]; }).join(", "));
  }
  process.exit(0);
})().catch(function (err) {
  console.error("SMOKE TEST FAILED:", err.message);
  console.error(err.stack);
  process.exit(1);
});
