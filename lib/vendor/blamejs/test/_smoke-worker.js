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
    process.stdout.write("\n" + JSON.stringify({
      ok:     true,
      checks: helpers.getChecks(),
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
