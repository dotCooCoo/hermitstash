/**
 * Full-server wrapped-mode integration tests.
 *
 * Unlike the other integration tests which exercise vault/backup/restore
 * modules in isolation, these tests spawn the actual `node server.js` as
 * a child process under VAULT_PASSPHRASE_MODE=required and exercise the
 * real HTTP surface. Proves the full boot → serve → shutdown path works
 * identically in wrapped mode as in plaintext mode.
 *
 * Scope:
 *   - First-run wrapped boot (fresh data dir, mode=required, env passphrase)
 *   - /health endpoint responds
 *   - Graceful SIGTERM shutdown
 *   - Re-boot with the same passphrase after shutdown (unwrap path)
 *   - Boot rejection on wrong passphrase
 *   - Rotation CLI: boot → rotate offline → re-boot with new passphrase
 *
 * NOT in scope (covered by other tests):
 *   - Vault-wrap format details (see unit/vault-wrap.test.js)
 *   - Passphrase source drivers (see unit/passphrase-source.test.js)
 *   - Setup/remove CLI (see integration/vault-passphrase.test.js)
 *   - Rotation CLI internals (see integration/vault-passphrase-rotate.test.js)
 *   - S3 backup in wrapped mode (full sync-E2E coverage requires
 *     runner-level data-dir isolation, exercised through the sync repo)
 */
var { describe, it, beforeEach, afterEach } = require("node:test");
var assert = require("node:assert");
var fs = require("fs");
var os = require("os");
var path = require("path");
var http = require("http");
var net = require("net");
var { spawn, spawnSync } = require("child_process");

var REPO_ROOT = path.resolve(__dirname, "..", "..");

function freshDataDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hs-fullboot-"));
}

function cleanup(dir, child) {
  if (child && !child.killed) {
    try { child.kill("SIGKILL"); } catch (_e) { /* already dead */ }
  }
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
}

// Start server.js with the given env, return the child process. Caller
// awaits startup via waitForHealth().
function startServer(dataDir, port, env) {
  var fullEnv = Object.assign({}, process.env, {
    HERMITSTASH_DATA_DIR: dataDir,
    HERMITSTASH_DB_PATH: path.join(dataDir, "hermitstash.db"),
    HERMITSTASH_ALLOW_DISK_DB: "true",
    HERMITSTASH_TMPDIR: dataDir,
    UPLOAD_DIR: path.join(dataDir, "uploads"),
    ARGON2_FAST: "1",
    PQC_ENFORCE: "false",
    // Do NOT set SETUP_COMPLETE — the integration test reboots the server
    // multiple times. Once SETUP_COMPLETE is true, the startup check fails
    // hard if the default admin email is still present, which it is in a
    // bare-bones integration test.
    EMAIL_VERIFICATION: "false",
    SESSION_SECRET: "integration-test-" + Math.random(),
    PORT: String(port),
    NODE_ENV: "test",
  }, env || {});
  var child = spawn(process.execPath, ["server.js"], {
    cwd: REPO_ROOT, env: fullEnv, stdio: ["pipe", "pipe", "pipe"], windowsHide: true,
  });
  child._stdout = "";
  child._stderr = "";
  child.stdout.on("data", function (d) { child._stdout += d.toString(); });
  child.stderr.on("data", function (d) { child._stderr += d.toString(); });
  return child;
}

// Poll /health until 200 or timeout. Returns null on success, error string on fail.
function waitForHealth(port, timeoutMs) {
  var deadline = Date.now() + (timeoutMs || 15000);
  return new Promise(function (resolve) {
    (function poll() {
      var req = http.get({ host: "127.0.0.1", port: port, path: "/health", timeout: 1000 }, function (res) {
        res.resume();
        if (res.statusCode === 200) return resolve(null);
        retry();
      });
      req.on("error", retry);
      req.on("timeout", function () { req.destroy(); retry(); });
      function retry() {
        if (Date.now() > deadline) return resolve("timeout");
        setTimeout(poll, 200);
      }
    })();
  });
}

// Gracefully shut down the child, waiting for the process to exit.
function stopServer(child, timeoutMs) {
  return new Promise(function (resolve) {
    if (!child || child.killed) return resolve();
    var settled = false;
    var t = setTimeout(function () {
      if (!settled) {
        try { child.kill("SIGKILL"); } catch (_e) { /* already dead */ }
        settled = true; resolve();
      }
    }, timeoutMs || 5000);
    child.once("exit", function () {
      if (!settled) { clearTimeout(t); settled = true; resolve(); }
    });
    try { child.kill("SIGTERM"); } catch (_e) { /* already dead */ }
  });
}

// Ask the OS for a free ephemeral port by binding to 0 then closing.
// On Windows this avoids Hyper-V's reserved port ranges (40000-50000 commonly)
// which intermittently broke randPort()'s 45000-55000 range. Brief TOCTOU is
// acceptable since each test owns its port and the OS won't immediately reuse.
async function pickPort() {
  return new Promise(function (resolve, reject) {
    var srv = net.createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", function () {
      var port = srv.address().port;
      srv.close(function () { resolve(port); });
    });
  });
}

describe("full-server wrapped-mode boot", function () {
  var dir, child, port;
  beforeEach(async function () {
    dir = freshDataDir();
    port = await pickPort();
  });
  afterEach(async function () {
    await stopServer(child);
    cleanup(dir);
    child = null;
  });

  it("first-run wrapped boot generates vault.key.sealed and serves /health", async function () {
    child = startServer(dir, port, {
      VAULT_PASSPHRASE_MODE: "required",
      VAULT_PASSPHRASE: "integration-pw",
    });
    var err = await waitForHealth(port, 15000);
    assert.strictEqual(err, null, "server did not reach healthy state: " + (child._stderr || "(no stderr)"));
    // File invariants
    assert.ok(fs.existsSync(path.join(dir, "vault.key.sealed")), "vault.key.sealed must exist");
    assert.ok(!fs.existsSync(path.join(dir, "vault.key")), "plaintext vault.key must NOT exist in wrapped mode");
    // Stdout signal
    assert.match(child._stdout, /Generated and sealed new vault keypair/, "startup log should confirm wrapped keypair was generated");
  });

  it("re-boot with same passphrase unwraps existing sealed file", async function () {
    // First boot: generate wrapped keypair
    child = startServer(dir, port, {
      VAULT_PASSPHRASE_MODE: "required",
      VAULT_PASSPHRASE: "integration-pw",
    });
    assert.strictEqual(await waitForHealth(port, 15000), null, "first boot failed");
    await stopServer(child);

    // Second boot: unwrap existing sealed file
    child = startServer(dir, port, {
      VAULT_PASSPHRASE_MODE: "required",
      VAULT_PASSPHRASE: "integration-pw",
    });
    var err = await waitForHealth(port, 15000);
    assert.strictEqual(err, null, "second boot (unwrap path) failed: " + child._stderr);
    assert.match(child._stdout, /Unsealed successfully/, "startup log should confirm unseal");
  });

  it("boot with wrong passphrase fails fast with passphrase-rejected", async function () {
    // Seed a sealed file with one passphrase
    child = startServer(dir, port, {
      VAULT_PASSPHRASE_MODE: "required",
      VAULT_PASSPHRASE: "correct-pw",
    });
    assert.strictEqual(await waitForHealth(port, 15000), null, "initial seed boot failed");
    await stopServer(child);
    child = null;

    // Try to boot with the wrong passphrase
    var port2 = await pickPort();
    child = startServer(dir, port2, {
      VAULT_PASSPHRASE_MODE: "required",
      VAULT_PASSPHRASE: "wrong-pw",
    });
    // Should exit non-zero quickly; /health should never come up
    var err = await waitForHealth(port2, 5000);
    assert.ok(err, "server should NOT have reached healthy state with wrong passphrase");
    // Give the process time to exit on its own
    await new Promise(function (r) { setTimeout(r, 1000); });
    assert.match(child._stderr, /passphrase rejected|rejected or sealed file corrupted/, "stderr should indicate passphrase rejection");
    child = null;
  });

  it("full rotation flow: boot → rotate offline → re-boot with new passphrase", async function () {
    // 1. Initial boot wraps keys with "old-pw"
    child = startServer(dir, port, {
      VAULT_PASSPHRASE_MODE: "required",
      VAULT_PASSPHRASE: "old-pw",
    });
    assert.strictEqual(await waitForHealth(port, 15000), null, "initial boot failed");
    await stopServer(child);
    child = null;

    // 2. Rotate offline via CLI
    var rotateEnv = Object.assign({}, process.env, {
      HERMITSTASH_DATA_DIR: dir,
      ARGON2_FAST: "1",
      VAULT_PASSPHRASE_OLD: "old-pw",
      VAULT_PASSPHRASE_NEW: "new-pw",
    });
    var rotate = spawnSync("node", [
      "scripts/vault-passphrase-rotate.js",
      "--force-with-server-running",
    ], {
      cwd: REPO_ROOT, env: rotateEnv, encoding: "utf8", timeout: 30000,
    });
    assert.strictEqual(rotate.status, 0, "rotate failed: " + rotate.stderr);

    // 3. Re-boot with new passphrase
    var port2 = await pickPort();
    child = startServer(dir, port2, {
      VAULT_PASSPHRASE_MODE: "required",
      VAULT_PASSPHRASE: "new-pw",
    });
    var err = await waitForHealth(port2, 15000);
    assert.strictEqual(err, null, "re-boot after rotation failed: " + child._stderr);
    assert.match(child._stdout, /Unsealed successfully/);
  });

  it("boot with VAULT_PASSPHRASE_FILE instead of env var", async function () {
    var pwFile = path.join(dir, "passphrase-file");
    fs.writeFileSync(pwFile, "file-based-pw\n", { mode: 0o600 });

    child = startServer(dir, port, {
      VAULT_PASSPHRASE_MODE: "required",
      VAULT_PASSPHRASE_FILE: pwFile,
    });
    var err = await waitForHealth(port, 15000);
    assert.strictEqual(err, null, "file-source boot failed: " + child._stderr);
    // Verify the passphrase was read from the file (boot succeeded with the file-content passphrase)
    await stopServer(child);

    // Re-boot with different file content should fail
    fs.writeFileSync(pwFile, "wrong-content\n");
    var port2 = await pickPort();
    child = startServer(dir, port2, {
      VAULT_PASSPHRASE_MODE: "required",
      VAULT_PASSPHRASE_FILE: pwFile,
    });
    var err2 = await waitForHealth(port2, 5000);
    assert.ok(err2, "boot with wrong file content should have failed");
    child = null;
  });

  it("plaintext-mode boot still works (zero regression)", async function () {
    // No VAULT_PASSPHRASE_MODE = default plaintext
    child = startServer(dir, port, {});
    var err = await waitForHealth(port, 15000);
    assert.strictEqual(err, null, "plaintext boot failed: " + child._stderr);
    assert.ok(fs.existsSync(path.join(dir, "vault.key")), "plaintext vault.key should exist");
    assert.ok(!fs.existsSync(path.join(dir, "vault.key.sealed")), "sealed file should NOT exist in plaintext mode");
  });
});
