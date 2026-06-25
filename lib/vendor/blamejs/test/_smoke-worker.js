"use strict";
/**
 * Smoke test worker — forked child that runs ONE test file's run()
 * in a fresh Node process. Module-state isolation is automatic
 * because the worker has its own module cache.
 *
 * Invocation: node test/_smoke-worker.js <test-file-path>
 *
 * Output contract: the LAST line of stdout is a JSON result of shape
 *   { ok: boolean, checks: number, error?: string }
 *
 * Other stdout/stderr lines are forwarded to the parent for display
 * on failure (the parent only prints them when ok=false).
 */

var path = require("node:path");
var modulePath = process.argv[2];
if (!modulePath) {
  process.stderr.write("usage: _smoke-worker.js <test-file-path>\n");
  process.exit(2);
}

// Capture a FIRE-AND-FORGET async failure — an unawaited promise that rejects,
// or a handle callback (socket / timer / server) that throws — that fires
// AFTER the test's assertions have already passed. Without this, Node's default
// unhandled-rejection handling bumps the exit code to 1 and RACES the worker's
// own process.exit(0): on a fast runner exit(0) usually wins (the leak is
// invisible), but on a slow / starved runner (macos-latest, 3 cores) the
// rejection wins first and the file reads as an unattributable "fork failed".
// Recording it lets the worker report it DETERMINISTICALLY, named to this test,
// on every runner — turning an intermittent CI flake into a reproducible bug.
var _lateError = null;
function _recordLate(kind, err) { if (!_lateError) _lateError = { kind: kind, err: err }; }
process.on("unhandledRejection", function (reason) { _recordLate("unhandledRejection", reason); });
process.on("uncaughtException",  function (err)    { _recordLate("uncaughtException", err); });

// Leaked-handle audit. A test that schedules async work it never cancels — a
// retry timer, a shutdown wait, a watcher/reload restart, an unclosed server /
// socket / db connection / worker thread — leaves a handle that keeps the
// event loop alive. process.exit(0) hides it locally (it force-exits), but the
// lingering handle is what delays a slow CI runner and is the same root that,
// when its callback later throws, becomes a late "fork failed". Snapshot the
// handles the module holds BEFORE run() (load-time handles are legitimate),
// then diff AFTER run() so only handles created-and-not-released during the
// test are reported. Report-only (a leak doesn't fail the file) so the sweep
// surfaces the population without a flag-day; Immediate/TickObject are the
// worker's own exit scheduling and are ignored.
function _handleCounts() {
  if (typeof process.getActiveResourcesInfo !== "function") return null;
  var c = {};
  process.getActiveResourcesInfo().forEach(function (t) { c[t] = (c[t] || 0) + 1; });
  return c;
}
// Infrastructure resource types that are NOT leaks: the worker's own exit
// scheduling (Immediate / TickObject) and the stdio + IPC pipes (PipeWrap /
// TTYWrap), which only register as "active" once written to — a test writing
// its own "OK" line activates stdout AFTER the baseline snapshot, so they would
// otherwise show as a phantom +1. The leaks we care about keep the event loop
// alive across the grace tick: Timeout, TCP*/Server, FSEvent/StatWatcher,
// MessagePort (un-terminated Worker), TLSWrap, FSReqCallback, etc.
var _HANDLE_IGNORE = { Immediate: 1, TickObject: 1, PipeWrap: 1, TTYWrap: 1 };
function _leakedHandles(baseline) {
  var now = _handleCounts();
  if (!now || !baseline) return [];
  var out = [];
  Object.keys(now).forEach(function (t) {
    if (_HANDLE_IGNORE[t]) return;
    var delta = now[t] - (baseline[t] || 0);
    if (delta > 0) out.push(t + (delta > 1 ? " x" + delta : ""));
  });
  return out;
}
var _baselineHandles = null;

(async function () {
  var helpers, mod;
  try {
    helpers = require("./helpers");
    mod = require(path.resolve(modulePath));
  } catch (e) {
    process.stdout.write("\n" + JSON.stringify({
      ok:    false,
      checks: 0,
      error: "module load failed: " + (e && e.message),
    }));
    process.exit(1);
  }
  try {
    // Snapshot load-time handles so the post-run diff only reports handles the
    // TEST created and never released (not ones the module legitimately holds).
    _baselineHandles = _handleCounts();
    if (typeof mod.run === "function") await mod.run();
    if (Array.isArray(mod.groups) && mod.groups.length > 0) {
      for (var i = 0; i < mod.groups.length; i++) {
        var group = mod.groups[i];
        var ctx = null;
        try {
          if (typeof group.setup === "function") ctx = await group.setup();
          for (var j = 0; j < group.tests.length; j++) {
            await group.tests[j].run(ctx);
          }
        } finally {
          if (typeof group.teardown === "function") {
            try { await group.teardown(ctx); }
            catch (_te) { /* teardown errors don't mask test failures */ }
          }
        }
      }
    }
    // Let fire-and-forget microtasks / immediates settle so a late rejection or
    // teardown throw surfaces HERE, attributed to this test, instead of racing
    // process.exit(0) and reading as an unattributable "fork failed" on a slow
    // runner. Registering the handlers above also suppresses Node's default
    // exit-on-unhandled-rejection, so the worker — not a race — decides.
    await new Promise(function (r) { setImmediate(r); });
    await new Promise(function (r) { setImmediate(r); });
    if (_lateError) {
      var le = _lateError.err;
      process.stdout.write("\n" + JSON.stringify({
        ok:     false,
        checks: helpers.getChecks(),
        // lateError flags this as a process-level transient (a fire-and-forget
        // promise / unreleased handle that threw after the assertions passed),
        // so the parent retries it ONCE — a transient passes on retry, a
        // persistent one fails again and surfaces a real, reproducible bug.
        // Either way the file is now NAMED, not an unattributable "fork failed".
        lateError: true,
        error:  "assertions passed but a late " + _lateError.kind + " fired after run() — a " +
                "fire-and-forget promise or unreleased handle (retry timer, shutdown wait, " +
                "watcher/reload restart): " + ((le && le.message) || String(le)),
        stack:  le && le.stack,
      }));
      process.exit(1);
    }
    process.stdout.write("\n" + JSON.stringify({
      ok:     true,
      checks: helpers.getChecks(),
      leaks:  _leakedHandles(_baselineHandles),
    }));
    process.exit(0);
  } catch (err) {
    process.stdout.write("\n" + JSON.stringify({
      ok:     false,
      checks: helpers.getChecks(),
      error:  (err && err.message) || String(err),
      stack:  err && err.stack,
    }));
    process.exit(1);
  }
})();
