// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * scripts/test-integration.js
 *
 * Integration test runner. Validates the docker-compose.test.yml stack
 * is reachable, exports the test CA out of the docker volume, then
 * spawns each test in test/integration/ as its own node process with
 * NODE_EXTRA_CA_CERTS set so every TLS handshake the framework does
 * during the test trusts the CA — no rejectUnauthorized=false bypass
 * anywhere in the test surface.
 *
 * Distinct from `test/smoke.js` because the smoke gate must remain
 * pure — runs in CI, in prepack-guard, on a developer laptop with no
 * docker stack — and a "skip silently when service is down" branch in
 * a layer-N test makes that gate's pass count misleading and masks
 * bugs that only surface against a live backend.
 *
 * Exit codes:
 *   0 — every integration test passed
 *   1 — one or more services unreachable (rerun after `docker compose up`)
 *   2 — at least one test file threw / returned non-zero
 *   3 — script-level error (no test files found, CA export failed, etc.)
 *
 * Usage:
 *   node scripts/test-integration.js
 *   node scripts/test-integration.js queue-redis           — single test
 *   node scripts/test-integration.js --skip-service-check  — assume up
 */
var fs   = require("node:fs");
var os   = require("node:os");
var path = require("node:path");
var spawn = require("node:child_process").spawn;

var INTEGRATION_DIR = path.join(__dirname, "..", "test", "integration");
var CHECK_SERVICES  = path.join(__dirname, "check-services.js");
var CA_EXPORT_PATH  = path.join(os.tmpdir(), "blamejs-test-ca.crt");

function _padRight(s, n) {
  s = String(s);
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

function _spawn(cmd, args, opts) {
  return new Promise(function (resolve, reject) {
    var child = spawn(cmd, args, Object.assign({ stdio: "inherit" }, opts || {}));
    child.once("exit", function (code, signal) {
      resolve({ code: code, signal: signal });
    });
    child.once("error", reject);
  });
}

function _spawnCapturing(cmd, args, env) {
  return new Promise(function (resolve, reject) {
    var child = spawn(cmd, args, { env: env, stdio: ["ignore", "pipe", "pipe"] });
    var stdout = "";
    var stderr = "";
    child.stdout.on("data", function (b) { stdout += b.toString(); });
    child.stderr.on("data", function (b) { stderr += b.toString(); });
    child.once("exit", function (code, signal) {
      resolve({ code: code, signal: signal, stdout: stdout, stderr: stderr });
    });
    child.once("error", reject);
  });
}

async function _exportCaCert() {
  // The pki-init container exits after generating certs, so we copy
  // from any container that mounts the certs volume — redis is always
  // up and has /certs read-only.
  var rv = await _spawnCapturing("docker", ["cp", "blamejs-test-redis:/certs/ca.crt", CA_EXPORT_PATH], process.env);
  if (rv.code !== 0) {
    throw new Error("docker cp ca.crt failed: " + (rv.stderr || rv.stdout || "").trim());
  }
  if (!fs.existsSync(CA_EXPORT_PATH)) {
    throw new Error("ca.crt not present at " + CA_EXPORT_PATH + " after docker cp");
  }
  var pem = fs.readFileSync(CA_EXPORT_PATH, "utf8");
  if (pem.indexOf("-----BEGIN CERTIFICATE-----") !== 0) {
    throw new Error("exported ca.crt does not look like a PEM cert");
  }
  return CA_EXPORT_PATH;
}

(async function main() {
  var args = process.argv.slice(2);
  var skipCheck = args.indexOf("--skip-service-check") !== -1;
  var named = args.filter(function (a) { return a.charAt(0) !== "-"; });

  if (!fs.existsSync(INTEGRATION_DIR)) {
    console.error("[test-integration] missing dir: " + INTEGRATION_DIR);
    process.exit(3);
  }

  var files = fs.readdirSync(INTEGRATION_DIR)
    .filter(function (f) { return f.endsWith(".test.js"); })
    .filter(function (f) {
      if (named.length === 0) return true;
      return named.some(function (n) { return f === n || f === n + ".test.js"; });
    })
    .sort();

  if (files.length === 0) {
    console.error("[test-integration] no test files matched " +
      (named.length === 0 ? "test/integration/*.test.js" : named.join(", ")));
    process.exit(3);
  }

  if (!skipCheck) {
    console.log("[test-integration] running scripts/check-services.js gate...");
    var checkExit = await _spawn(process.execPath, [CHECK_SERVICES]);
    if (checkExit.code !== 0) {
      console.error("[test-integration] service-check gate failed (exit " + checkExit.code + ")");
      console.error("[test-integration] bring the stack up: docker compose -f docker-compose.test.yml up -d --wait");
      console.error("[test-integration] OR re-run with --skip-service-check to bypass");
      process.exit(1);
    }
  }

  // Export the test CA so each test process trusts it at startup. This
  // is the cleanest way to test against private TLS endpoints without
  // weakening the framework's verification — operators in production
  // do exactly the same thing (set NODE_EXTRA_CA_CERTS or trust the
  // CA at the OS level).
  var caPath;
  try {
    caPath = await _exportCaCert();
    console.log("[test-integration] CA exported: " + caPath);
  } catch (e) {
    console.error("[test-integration] CA export failed: " + e.message);
    process.exit(3);
  }

  var childEnv = Object.assign({}, process.env, {
    NODE_EXTRA_CA_CERTS:           caPath,
    BLAMEJS_TEST_CA_PATH:          caPath,
    BLAMEJS_INTEGRATION_RUNNER:    "1",
  });

  console.log("");
  console.log("[test-integration] running " + files.length + " integration test file" +
    (files.length === 1 ? "" : "s") + " (each in a fresh node process)...");
  var suiteStart = Date.now();
  var failed = 0;
  for (var i = 0; i < files.length; i++) {
    var fullPath = path.join(INTEGRATION_DIR, files[i]);
    var fileStart = Date.now();
    var rv;
    try {
      rv = await _spawnCapturing(process.execPath, [fullPath], childEnv);
    } catch (err) {
      failed += 1;
      console.error("  " + _padRight(files[i], 40) + " SPAWN FAILED");
      console.error("    " + (err.message || String(err)));
      continue;
    }
    var ms = Date.now() - fileStart;
    if (rv.code === 0) {
      // Success line: pull the trailing OK line out of stdout so the
      // runner output stays consistent with smoke's format.
      var okLine = (rv.stdout.match(/OK — \d+ checks? passed/g) || []).pop() || "";
      console.log("  " + _padRight(files[i], 40) + " (" + ms + "ms) " + okLine);
    } else {
      failed += 1;
      console.error("  " + _padRight(files[i], 40) + " FAILED (exit " + rv.code + ")");
      var lines = (rv.stderr || rv.stdout || "").split(/\r?\n/).filter(Boolean).slice(-12);
      lines.forEach(function (l) { console.error("    " + l); });
    }
  }
  console.log("");
  if (failed === 0) {
    console.log("[test-integration] OK — " + files.length + " files in " +
      (Date.now() - suiteStart) + "ms");
    process.exit(0);
  }
  console.error("[test-integration] " + failed + " of " + files.length + " files failed");
  process.exit(2);
})().catch(function (err) {
  console.error("[test-integration] runner error: " + ((err && err.stack) || err));
  process.exit(3);
});
