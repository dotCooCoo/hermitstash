"use strict";

/**
 * Requiring the audit module must not keep a process alive.
 *
 * Three schedulers start when it loads — retention cleanup, the archival check
 * and chain checkpointing. Each pairs an initial setTimeout with a repeating
 * setInterval, and in each one only the interval was unref'd. A timer that has
 * to elapse before the runtime will exit holds the process for exactly as long
 * as it is set for, so the longest of the three, a minute, is what every short
 * process paid: each test file that reached the audit module sat idle for a
 * minute after its assertions finished, and so would any script or one-shot
 * command that touched it.
 *
 * The server never noticed, which is why it survived — an unref'd timer still
 * fires while a listening socket keeps the loop running, so nothing about
 * scheduled behaviour changes either way.
 */

var { describe, it } = require("node:test");
var assert = require("node:assert");
var os = require("node:os");
var path = require("node:path");
var fs = require("node:fs");
var { spawnSync } = require("node:child_process");

var projectRoot = path.join(__dirname, "..", "..");

// How long a process is allowed to take to exit on its own after requiring a
// module. Generously above the ~0.5s it actually costs, and far below the 60s
// the un-unref'd timer produced, so the test is about the defect rather than
// about machine speed.
var LIMIT_MS = 20000;

function msToExitAfterRequiring(mod) {
  var tmp = fs.mkdtempSync(path.join(os.tmpdir(), "hs-timer-"));
  var target = path.join(projectRoot, mod).replace(/\\/g, "/");
  var script = [
    "process.env.HERMITSTASH_DATA_DIR = " + JSON.stringify(tmp) + ";",
    "process.env.HERMITSTASH_DB_PATH = " + JSON.stringify(path.join(tmp, "t.db")) + ";",
    "process.env.HERMITSTASH_ALLOW_DISK_DB = 'true';",
    "require(" + JSON.stringify(target) + ");",
  ].join("\n");

  var started = Date.now();
  var res = spawnSync(process.execPath, ["-e", script], {
    cwd: projectRoot, stdio: ["ignore", "pipe", "pipe"], timeout: LIMIT_MS + 40000,
  });
  var elapsed = Date.now() - started;
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_e) { /* best effort */ }

  // A child that dies on the require also exits quickly, and "quickly" is the
  // whole assertion — without this a broken import would read as a pass.
  return { ms: elapsed, status: res.status, signal: res.signal, stderr: String(res.stderr || "") };
}

describe("loading the audit subsystem does not hold a process open", function () {
  // The module itself, and the two that reach it — the cost was inherited by
  // everything downstream, which is how it came to affect most of the suite.
  ["lib/audit", "lib/audit-archive", "middleware/require-admin", "routes/stash"].forEach(function (mod) {
    it("requiring " + mod + " exits promptly", function () {
      var r = msToExitAfterRequiring(mod);
      assert.equal(r.signal, null, "the child was killed rather than exiting: " + r.stderr.slice(0, 300));
      assert.equal(r.status, 0,
        "requiring " + mod + " must succeed, or a fast exit proves nothing: " + r.stderr.slice(0, 300));
      assert.ok(r.ms < LIMIT_MS,
        "requiring " + mod + " took " + r.ms + "ms to exit; a pending timer is probably "
        + "missing its unref() — check the setTimeout paired with each setInterval "
        + "in lib/audit.js and lib/audit-archive.js");
    });
  });
});
