/**
 * Integration tests for opt-in vault passphrase wrapping.
 *
 * Covers the state machine dispatch, end-to-end setup → boot → remove flow,
 * and crash-recovery via migration markers.
 *
 * Uses ARGON2_FAST=1 child-process env so tests complete in seconds, not
 * minutes. Each test runs in an isolated temp data dir.
 */
var { describe, it, beforeEach, afterEach } = require("node:test");
var assert = require("node:assert");
var fs = require("fs");
var os = require("os");
var path = require("path");
var { spawnSync } = require("child_process");

var REPO_ROOT = path.resolve(__dirname, "..", "..");

function freshDataDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hs-vault-it-"));
}

function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
}

// Helper: run a node snippet with a fixed data dir, return { status, stdout, stderr }
function runNode(script, env) {
  var fullEnv = Object.assign({}, process.env, env || {});
  var r = spawnSync("node", ["-e", script], {
    cwd: REPO_ROOT,
    env: fullEnv,
    encoding: "utf8",
    timeout: 60000,
  });
  return { status: r.status, stdout: r.stdout || "", stderr: r.stderr || "" };
}

// Helper: run the setup CLI. Always passes --force-with-server-running
// because tests use isolated data dirs and the port check would produce
// false positives if an unrelated server is bound to 3000 on the dev box.
function runSetup(dataDir, env, args) {
  var fullEnv = Object.assign({
    HERMITSTASH_DATA_DIR: dataDir,
    ARGON2_FAST: "1",
    VAULT_PASSPHRASE_SOURCE: "env",
  }, process.env, env || {});
  var allArgs = ["scripts/vault-passphrase-setup.js", "--force-with-server-running"].concat(args || []);
  var r = spawnSync("node", allArgs, {
    cwd: REPO_ROOT, env: fullEnv, encoding: "utf8", timeout: 60000,
  });
  return { status: r.status, stdout: r.stdout || "", stderr: r.stderr || "" };
}

function runRemove(dataDir, env, args) {
  var fullEnv = Object.assign({
    HERMITSTASH_DATA_DIR: dataDir,
    ARGON2_FAST: "1",
    VAULT_PASSPHRASE_SOURCE: "env",
  }, process.env, env || {});
  var allArgs = ["scripts/vault-passphrase-remove.js", "--force-with-server-running"].concat(args || []);
  var r = spawnSync("node", allArgs, {
    cwd: REPO_ROOT, env: fullEnv, encoding: "utf8", timeout: 60000,
  });
  return { status: r.status, stdout: r.stdout || "", stderr: r.stderr || "" };
}

// Helper: boot vault.init() in a child process and report success/failure
function bootVault(dataDir, env) {
  var script = [
    "(async () => {",
    "  var vault = require('./lib/vault');",
    "  try { await vault.init(); }",
    "  catch (e) { console.error('boot-error:', e.message); process.exit(1); }",
    "  var back = vault.unseal(vault.seal('probe-data'));",
    "  if (back !== 'probe-data') { console.error('seal-roundtrip-failed'); process.exit(2); }",
    "  console.log('boot-ok');",
    "})().catch(function(e){ console.error('unexpected:', e.message); process.exit(3); });",
  ].join("");
  return runNode(script, Object.assign({
    HERMITSTASH_DATA_DIR: dataDir,
    ARGON2_FAST: "1",
    VAULT_PASSPHRASE_SOURCE: "env",
  }, env || {}));
}

// Helper: seed a fresh plaintext vault.key
function seedPlaintext(dataDir) {
  var script = [
    "var fs = require('fs');",
    "var C = require('./lib/constants');",
    "var { generateEncryptionKeyPair } = require('./lib/crypto');",
    "var keys = generateEncryptionKeyPair();",
    "fs.writeFileSync(C.PATHS.VAULT_KEY, JSON.stringify(keys, null, 2), { mode: 0o600 });",
    "console.log('seeded');",
  ].join("");
  var r = runNode(script, { HERMITSTASH_DATA_DIR: dataDir });
  assert.strictEqual(r.status, 0, "seedPlaintext: " + r.stderr);
}

describe("vault-passphrase integration: state machine dispatch", function () {
  var dir;
  beforeEach(function () { dir = freshDataDir(); });
  afterEach(function () { cleanup(dir); });

  it("plaintext + disabled → boots normally", function () {
    seedPlaintext(dir);
    var r = bootVault(dir);
    assert.strictEqual(r.status, 0, r.stderr);
    assert.match(r.stdout, /boot-ok/);
  });

  it("first-run + disabled → generates plaintext vault.key and boots", function () {
    var r = bootVault(dir);
    assert.strictEqual(r.status, 0, r.stderr);
    assert.match(r.stdout, /boot-ok/);
    assert.ok(fs.existsSync(path.join(dir, "vault.key")), "vault.key should have been generated");
    assert.ok(!fs.existsSync(path.join(dir, "vault.key.sealed")), "sealed should NOT exist");
  });

  it("plaintext + mode=required → aborts with config-mismatch message", function () {
    seedPlaintext(dir);
    var r = bootVault(dir, { VAULT_PASSPHRASE_MODE: "required", VAULT_PASSPHRASE: "pw" });
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr, /plaintext but VAULT_PASSPHRASE_MODE=required/);
  });

  it("sealed + disabled → aborts with config-mismatch message", function () {
    // Create sealed via setup
    seedPlaintext(dir);
    var setup = runSetup(dir, { VAULT_PASSPHRASE: "pw" });
    assert.strictEqual(setup.status, 0, "setup failed: " + setup.stderr);
    // Now boot with mode disabled (unset)
    var r = bootVault(dir, { VAULT_PASSPHRASE_MODE: "" });
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr, /sealed exists but VAULT_PASSPHRASE_MODE is disabled/);
  });

  it("both files exist → aborts with invariant violation", function () {
    seedPlaintext(dir);
    // Create an arbitrary sealed file too
    fs.writeFileSync(path.join(dir, "vault.key.sealed"), "bogus");
    var r = bootVault(dir, { VAULT_PASSPHRASE_MODE: "required", VAULT_PASSPHRASE: "pw" });
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr, /Both .* exist/);
  });

  it("first-run + mode=required → generates wrapped vault.key.sealed", function () {
    var r = bootVault(dir, { VAULT_PASSPHRASE_MODE: "required", VAULT_PASSPHRASE: "fresh-pw" });
    assert.strictEqual(r.status, 0, r.stderr);
    assert.match(r.stdout, /boot-ok/);
    assert.ok(fs.existsSync(path.join(dir, "vault.key.sealed")), "sealed should have been generated");
    assert.ok(!fs.existsSync(path.join(dir, "vault.key")), "plaintext should NOT exist");
  });

  it("wrong passphrase on wrapped boot → aborts with rejection", function () {
    seedPlaintext(dir);
    var setup = runSetup(dir, { VAULT_PASSPHRASE: "correct" });
    assert.strictEqual(setup.status, 0, setup.stderr);
    var r = bootVault(dir, { VAULT_PASSPHRASE_MODE: "required", VAULT_PASSPHRASE: "wrong" });
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr, /passphrase rejected|rejected or sealed file corrupted/);
  });

  it("orphan .tmp is cleaned on boot", function () {
    seedPlaintext(dir);
    fs.writeFileSync(path.join(dir, "vault.key.sealed.tmp"), "orphan-bytes");
    var r = bootVault(dir);
    assert.strictEqual(r.status, 0, r.stderr);
    assert.ok(!fs.existsSync(path.join(dir, "vault.key.sealed.tmp")), "orphan .tmp should be cleaned");
  });
});

describe("vault-passphrase integration: setup CLI", function () {
  var dir;
  beforeEach(function () { dir = freshDataDir(); });
  afterEach(function () { cleanup(dir); });

  it("setup + boot wrapped + remove + boot plaintext — full round trip", function () {
    // 1. Seed plaintext
    seedPlaintext(dir);
    var plaintextBefore = fs.readFileSync(path.join(dir, "vault.key"));

    // 2. Run setup
    var setup = runSetup(dir, { VAULT_PASSPHRASE: "pw-integration" });
    assert.strictEqual(setup.status, 0, "setup failed: " + setup.stderr);
    assert.ok(fs.existsSync(path.join(dir, "vault.key.sealed")));
    assert.ok(!fs.existsSync(path.join(dir, "vault.key")), "plaintext should be deleted by default");
    assert.ok(!fs.existsSync(path.join(dir, "vault.key.migration-pending")), "marker should be cleared");

    // 3. Boot wrapped
    var boot = bootVault(dir, { VAULT_PASSPHRASE_MODE: "required", VAULT_PASSPHRASE: "pw-integration" });
    assert.strictEqual(boot.status, 0, "wrapped boot failed: " + boot.stderr);

    // 4. Remove
    var remove = runRemove(dir, { VAULT_PASSPHRASE: "pw-integration" });
    assert.strictEqual(remove.status, 0, "remove failed: " + remove.stderr);
    assert.ok(fs.existsSync(path.join(dir, "vault.key")));
    assert.ok(!fs.existsSync(path.join(dir, "vault.key.sealed")));

    // 5. Plaintext content matches original (byte-identical)
    var plaintextAfter = fs.readFileSync(path.join(dir, "vault.key"));
    assert.strictEqual(Buffer.compare(plaintextBefore, plaintextAfter), 0,
      "plaintext after remove must match original byte-for-byte");

    // 6. Boot plaintext
    var bootP = bootVault(dir);
    assert.strictEqual(bootP.status, 0, "plaintext boot after remove failed: " + bootP.stderr);
  });

  it("setup --keep-plaintext leaves vault.key in place", function () {
    seedPlaintext(dir);
    var setup = runSetup(dir, { VAULT_PASSPHRASE: "pw" }, ["--keep-plaintext"]);
    assert.strictEqual(setup.status, 0, setup.stderr);
    assert.ok(fs.existsSync(path.join(dir, "vault.key.sealed")));
    assert.ok(fs.existsSync(path.join(dir, "vault.key")), "vault.key should be preserved");
    // And boot should fail with invariant violation (both files exist)
    var boot = bootVault(dir, { VAULT_PASSPHRASE_MODE: "required", VAULT_PASSPHRASE: "pw" });
    assert.notStrictEqual(boot.status, 0);
    assert.match(boot.stderr, /Both .* exist/);
  });

  it("setup refuses when sealed already exists", function () {
    seedPlaintext(dir);
    var s1 = runSetup(dir, { VAULT_PASSPHRASE: "pw1" });
    assert.strictEqual(s1.status, 0, s1.stderr);
    // Recreate plaintext (would normally be done by manually restoring from backup)
    seedPlaintext(dir);
    // Now both exist — but the refuse-check will hit sealed-already-exists first
    var s2 = runSetup(dir, { VAULT_PASSPHRASE: "pw2" });
    assert.notStrictEqual(s2.status, 0);
    assert.match(s2.stderr + s2.stdout, /already exists/);
  });

  it("setup refuses when vault.key is missing", function () {
    var r = runSetup(dir, { VAULT_PASSPHRASE: "pw" });
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr + r.stdout, /does not exist|nothing to migrate/);
  });

  it("setup refuses when stale .tmp is present", function () {
    seedPlaintext(dir);
    fs.writeFileSync(path.join(dir, "vault.key.sealed.tmp"), "stale");
    var r = runSetup(dir, { VAULT_PASSPHRASE: "pw" });
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr + r.stdout, /stale/);
  });
});

describe("vault-passphrase integration: migration marker recovery", function () {
  var dir;
  beforeEach(function () { dir = freshDataDir(); });
  afterEach(function () { cleanup(dir); });

  it("recovers from crash between sealed-rename and plaintext-unlink", function () {
    // Simulate the state: vault.key + vault.key.sealed + migration-pending exist
    // with correct sha3.
    seedPlaintext(dir);
    var setup = runSetup(dir, { VAULT_PASSPHRASE: "pw" }, ["--keep-plaintext"]);
    assert.strictEqual(setup.status, 0, setup.stderr);
    // Now both exist. Simulate the crash by writing a correct marker.
    var { sha3Hash } = require("../../lib/crypto");
    var sealedBytes = fs.readFileSync(path.join(dir, "vault.key.sealed"));
    var marker = {
      format: 1,
      hashAlg: "sha3-512",
      startedAt: new Date().toISOString(),
      sealedSha3: sha3Hash(sealedBytes),
    };
    fs.writeFileSync(path.join(dir, "vault.key.migration-pending"), JSON.stringify(marker));
    // Boot: recovery should unlink vault.key and the marker, leaving sealed only.
    var boot = bootVault(dir, { VAULT_PASSPHRASE_MODE: "required", VAULT_PASSPHRASE: "pw" });
    assert.strictEqual(boot.status, 0, "recovery boot failed: " + boot.stderr);
    assert.ok(!fs.existsSync(path.join(dir, "vault.key")), "plaintext should have been deleted by recovery");
    assert.ok(!fs.existsSync(path.join(dir, "vault.key.migration-pending")), "marker should be cleared");
    assert.ok(fs.existsSync(path.join(dir, "vault.key.sealed")), "sealed should remain");
  });

  it("rejects marker with tampered sealedSha3", function () {
    seedPlaintext(dir);
    var setup = runSetup(dir, { VAULT_PASSPHRASE: "pw" }, ["--keep-plaintext"]);
    assert.strictEqual(setup.status, 0, setup.stderr);
    // Marker with WRONG hash
    var marker = {
      format: 1,
      hashAlg: "sha3-512",
      startedAt: new Date().toISOString(),
      sealedSha3: "0".repeat(128), // fake hash
    };
    fs.writeFileSync(path.join(dir, "vault.key.migration-pending"), JSON.stringify(marker));
    var boot = bootVault(dir, { VAULT_PASSPHRASE_MODE: "required", VAULT_PASSPHRASE: "pw" });
    assert.notStrictEqual(boot.status, 0);
    assert.match(boot.stderr, /hash does not match migration marker/);
  });

  it("discards marker when target file doesn't exist (crash before rename)", function () {
    seedPlaintext(dir);
    // Create a marker referencing a non-existent sealed file
    var marker = {
      format: 1,
      hashAlg: "sha3-512",
      startedAt: new Date().toISOString(),
      sealedSha3: "0".repeat(128),
    };
    fs.writeFileSync(path.join(dir, "vault.key.migration-pending"), JSON.stringify(marker));
    // Boot should discard marker and continue normally
    var boot = bootVault(dir);
    assert.strictEqual(boot.status, 0, boot.stderr);
    assert.ok(!fs.existsSync(path.join(dir, "vault.key.migration-pending")));
    assert.ok(fs.existsSync(path.join(dir, "vault.key")));
  });

  it("rejects malformed marker JSON", function () {
    seedPlaintext(dir);
    fs.writeFileSync(path.join(dir, "vault.key.migration-pending"), "not-json!{");
    var boot = bootVault(dir);
    assert.notStrictEqual(boot.status, 0);
    assert.match(boot.stderr, /marker.*unreadable/i);
  });
});
