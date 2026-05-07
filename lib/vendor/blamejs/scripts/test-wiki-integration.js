"use strict";
/**
 * scripts/test-wiki-integration.js
 *
 * Wiki-app integration runner. Validates the docker-compose.test.yml
 * stack, exports the test CA, then boots the wiki app against the live
 * backends and runs examples/wiki/test/integration.js — the wiki's
 * end-to-end "real app against real services" gate.
 *
 * Distinct from `test/smoke.js` and `examples/wiki/test/e2e.js` (both
 * pure, no docker dependency, run in CI / on a developer laptop /
 * inside prepack-guard) and complementary to `scripts/test-integration.js`
 * (per-primitive integration tests). This runner exercises the wiki's
 * actual operational wiring — proving framework primitives work
 * end-to-end through the same boot path operators run in production.
 *
 * Exit codes:
 *   0 — wiki integration passed
 *   1 — service stack unreachable (rerun after `docker compose up`)
 *   2 — wiki integration failed
 *   3 — runner error (CA export failed, no test files found, etc.)
 */
var fs    = require("node:fs");
var os    = require("node:os");
var path  = require("node:path");
var spawn = require("node:child_process").spawn;

var WIKI_DIR        = path.join(__dirname, "..", "examples", "wiki");
var WIKI_TEST_FILE  = path.join(WIKI_DIR, "test", "integration.js");
var CHECK_SERVICES  = path.join(__dirname, "check-services.js");
var CA_EXPORT_PATH  = path.join(os.tmpdir(), "blamejs-test-ca.crt");

function _spawn(cmd, args, opts) {
  return new Promise(function (resolve, reject) {
    var child = spawn(cmd, args, Object.assign({ stdio: "inherit" }, opts || {}));
    child.once("exit", function (code, signal) { resolve({ code: code, signal: signal }); });
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
  var rv = await _spawnCapturing("docker",
    ["cp", "blamejs-test-redis:/certs/ca.crt", CA_EXPORT_PATH],
    process.env);
  if (rv.code !== 0) {
    throw new Error("docker cp ca.crt failed: " + (rv.stderr || rv.stdout || "").trim());
  }
  if (!fs.existsSync(CA_EXPORT_PATH)) {
    throw new Error("ca.crt not present at " + CA_EXPORT_PATH);
  }
  return CA_EXPORT_PATH;
}

(async function main() {
  var args = process.argv.slice(2);
  var skipCheck = args.indexOf("--skip-service-check") !== -1;

  if (!fs.existsSync(WIKI_TEST_FILE)) {
    console.error("[test-wiki-integration] missing test file: " + WIKI_TEST_FILE);
    process.exit(3);
  }

  if (!skipCheck) {
    console.log("[test-wiki-integration] running scripts/check-services.js gate...");
    var checkExit = await _spawn(process.execPath, [CHECK_SERVICES]);
    if (checkExit.code !== 0) {
      console.error("[test-wiki-integration] service-check gate failed (exit " + checkExit.code + ")");
      console.error("[test-wiki-integration] bring the stack up: docker compose -f docker-compose.test.yml up -d --wait");
      console.error("[test-wiki-integration] OR re-run with --skip-service-check to bypass");
      process.exit(1);
    }
  }

  // Export the CA so the wiki app's TLS handshakes (mailpit STARTTLS,
  // outbound HTTPS, redis-tls if exercised) trust the test CA without
  // a rejectUnauthorized:false bypass anywhere in the wiki surface.
  var caPath;
  try {
    caPath = await _exportCaCert();
    console.log("[test-wiki-integration] CA exported: " + caPath);
  } catch (e) {
    console.error("[test-wiki-integration] CA export failed: " + e.message);
    process.exit(3);
  }

  var childEnv = Object.assign({}, process.env, {
    NODE_EXTRA_CA_CERTS:        caPath,
    BLAMEJS_TEST_CA_PATH:       caPath,
    BLAMEJS_INTEGRATION_RUNNER: "1",
  });

  console.log("");
  console.log("[test-wiki-integration] booting wiki + running integration suite...");
  var start = Date.now();
  var rv = await _spawnCapturing(process.execPath, [WIKI_TEST_FILE], childEnv);
  var ms = Date.now() - start;

  // Stream child output so the operator sees progress + assertions.
  process.stdout.write(rv.stdout);
  if (rv.stderr) process.stderr.write(rv.stderr);

  console.log("");
  if (rv.code === 0) {
    console.log("[test-wiki-integration] OK — wiki integration green in " + ms + "ms");
    process.exit(0);
  }
  console.error("[test-wiki-integration] FAIL — wiki integration failed (exit " + rv.code + ", " + ms + "ms)");
  process.exit(2);
})().catch(function (err) {
  console.error("[test-wiki-integration] runner error: " + ((err && err.stack) || err));
  process.exit(3);
});
