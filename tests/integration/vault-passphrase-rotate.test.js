/**
 * Integration tests for the vault passphrase rotation CLI.
 */
var { describe, it, beforeEach, afterEach } = require("node:test");
var assert = require("node:assert");
var fs = require("fs");
var os = require("os");
var path = require("path");
var { spawnSync } = require("child_process");

var REPO_ROOT = path.resolve(__dirname, "..", "..");

function freshDataDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "hs-rotate-it-"));
}

function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* best effort */ }
}

function runSetup(dataDir, env) {
  var fullEnv = Object.assign({
    HERMITSTASH_DATA_DIR: dataDir,
    ARGON2_FAST: "1",
    VAULT_PASSPHRASE_SOURCE: "env",
  }, process.env, env || {});
  return spawnSync("node", ["scripts/vault-passphrase-setup.js", "--force-with-server-running"], {
    cwd: REPO_ROOT, env: fullEnv, encoding: "utf8", timeout: 60000,
  });
}

function runRotate(dataDir, env, args) {
  var fullEnv = Object.assign({
    HERMITSTASH_DATA_DIR: dataDir,
    ARGON2_FAST: "1",
  }, process.env, env || {});
  var allArgs = ["scripts/vault-passphrase-rotate.js", "--force-with-server-running"].concat(args || []);
  return spawnSync("node", allArgs, {
    cwd: REPO_ROOT, env: fullEnv, encoding: "utf8", timeout: 60000,
  });
}

function bootVault(dataDir, env) {
  var script = [
    "(async () => {",
    "  var vault = require('./lib/vault');",
    "  try { await vault.init(); }",
    "  catch (e) { console.error('boot-error:', e.message); process.exit(1); }",
    "  var back = vault.unseal(vault.seal('probe'));",
    "  if (back !== 'probe') { console.error('seal-roundtrip-failed'); process.exit(2); }",
    "  console.log('boot-ok');",
    "})().catch(function(e){ console.error('unexpected:', e.message); process.exit(3); });",
  ].join("");
  var fullEnv = Object.assign({
    HERMITSTASH_DATA_DIR: dataDir,
    ARGON2_FAST: "1",
    VAULT_PASSPHRASE_SOURCE: "env",
  }, process.env, env || {});
  return spawnSync("node", ["-e", script], {
    cwd: REPO_ROOT, env: fullEnv, encoding: "utf8", timeout: 60000,
  });
}

function seedPlaintext(dataDir) {
  var script = [
    "var fs = require('fs');",
    "var C = require('./lib/constants');",
    "var { generateEncryptionKeyPair } = require('./lib/crypto');",
    "var keys = generateEncryptionKeyPair();",
    "fs.writeFileSync(C.PATHS.VAULT_KEY, JSON.stringify(keys, null, 2), { mode: 0o600 });",
  ].join("");
  var r = spawnSync("node", ["-e", script], {
    cwd: REPO_ROOT,
    env: Object.assign({}, process.env, { HERMITSTASH_DATA_DIR: dataDir }),
    encoding: "utf8",
  });
  assert.strictEqual(r.status, 0, "seedPlaintext: " + r.stderr);
}

function setupWrapped(dataDir, passphrase) {
  seedPlaintext(dataDir);
  var r = runSetup(dataDir, { VAULT_PASSPHRASE: passphrase });
  assert.strictEqual(r.status, 0, "setup failed: " + r.stderr);
}

describe("vault-passphrase-rotate: env-based flow", function () {
  var dir;
  beforeEach(function () { dir = freshDataDir(); });
  afterEach(function () { cleanup(dir); });

  it("rotates the passphrase and boot works with the new one", function () {
    setupWrapped(dir, "old-pw-12345");

    var r = runRotate(dir, {
      VAULT_PASSPHRASE_OLD: "old-pw-12345",
      VAULT_PASSPHRASE_NEW: "new-pw-67890",
    });
    assert.strictEqual(r.status, 0, "rotate failed: " + r.stderr);

    // Boot with OLD passphrase should now FAIL
    var boot1 = bootVault(dir, { VAULT_PASSPHRASE_MODE: "required", VAULT_PASSPHRASE: "old-pw-12345" });
    assert.notStrictEqual(boot1.status, 0, "boot with old passphrase should have failed: " + boot1.stdout);

    // Boot with NEW passphrase should succeed
    var boot2 = bootVault(dir, { VAULT_PASSPHRASE_MODE: "required", VAULT_PASSPHRASE: "new-pw-67890" });
    assert.strictEqual(boot2.status, 0, "boot with new passphrase failed: " + boot2.stderr);
    assert.match(boot2.stdout, /boot-ok/);
  });

  it("rejects when old passphrase is wrong", function () {
    setupWrapped(dir, "correct-old");
    var r = runRotate(dir, {
      VAULT_PASSPHRASE_OLD: "wrong-old",
      VAULT_PASSPHRASE_NEW: "any-new",
    });
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr + r.stdout, /OLD passphrase rejected/);
    // Sealed file must be unchanged
    var boot = bootVault(dir, { VAULT_PASSPHRASE_MODE: "required", VAULT_PASSPHRASE: "correct-old" });
    assert.strictEqual(boot.status, 0, "sealed file should still work with original old pw: " + boot.stderr);
  });

  it("rejects when new == old", function () {
    setupWrapped(dir, "same-pw");
    var r = runRotate(dir, {
      VAULT_PASSPHRASE_OLD: "same-pw",
      VAULT_PASSPHRASE_NEW: "same-pw",
    });
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr + r.stdout, /identical to old passphrase/);
  });

  it("rejects partial env config (only OLD set)", function () {
    setupWrapped(dir, "pw");
    var r = runRotate(dir, { VAULT_PASSPHRASE_OLD: "pw" });
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr + r.stdout, /partial env passphrase config/);
  });

  it("rejects partial env config (only NEW set)", function () {
    setupWrapped(dir, "pw");
    var r = runRotate(dir, { VAULT_PASSPHRASE_NEW: "new-pw" });
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr + r.stdout, /partial env passphrase config/);
  });

  it("rejects when sealed file doesn't exist", function () {
    // No setup → no sealed file
    var r = runRotate(dir, {
      VAULT_PASSPHRASE_OLD: "a",
      VAULT_PASSPHRASE_NEW: "b",
    });
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr + r.stdout, /does not exist|nothing to rotate/);
  });

  it("rejects when stale .tmp is present", function () {
    setupWrapped(dir, "pw");
    fs.writeFileSync(path.join(dir, "vault.key.sealed.tmp"), "stale");
    var r = runRotate(dir, {
      VAULT_PASSPHRASE_OLD: "pw",
      VAULT_PASSPHRASE_NEW: "new-pw",
    });
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr + r.stdout, /stale/);
  });
});

describe("vault-passphrase-rotate: file-based flow", function () {
  var dir, oldFile, newFile;
  beforeEach(function () {
    dir = freshDataDir();
    oldFile = path.join(dir, "old-secret");
    newFile = path.join(dir, "new-secret");
  });
  afterEach(function () { cleanup(dir); });

  it("rotates via OLD_FILE + NEW_FILE", function () {
    setupWrapped(dir, "file-old");
    fs.writeFileSync(oldFile, "file-old\n");
    fs.writeFileSync(newFile, "file-new\n");
    var r = runRotate(dir, {
      VAULT_PASSPHRASE_OLD_FILE: oldFile,
      VAULT_PASSPHRASE_NEW_FILE: newFile,
    });
    assert.strictEqual(r.status, 0, "rotate failed: " + r.stderr);
    var boot = bootVault(dir, { VAULT_PASSPHRASE_MODE: "required", VAULT_PASSPHRASE: "file-new" });
    assert.strictEqual(boot.status, 0, boot.stderr);
  });
});

describe("vault-passphrase-rotate: end-to-end with setup", function () {
  var dir;
  beforeEach(function () { dir = freshDataDir(); });
  afterEach(function () { cleanup(dir); });

  it("setup → rotate → rotate-again → boot works with final passphrase", function () {
    setupWrapped(dir, "pw1");

    var r1 = runRotate(dir, { VAULT_PASSPHRASE_OLD: "pw1", VAULT_PASSPHRASE_NEW: "pw2" });
    assert.strictEqual(r1.status, 0, r1.stderr);

    var r2 = runRotate(dir, { VAULT_PASSPHRASE_OLD: "pw2", VAULT_PASSPHRASE_NEW: "pw3" });
    assert.strictEqual(r2.status, 0, r2.stderr);

    var boot = bootVault(dir, { VAULT_PASSPHRASE_MODE: "required", VAULT_PASSPHRASE: "pw3" });
    assert.strictEqual(boot.status, 0, boot.stderr);
  });

  it("rotation preserves the vault key contents (decrypted data unchanged)", function () {
    // Set up with a known plaintext
    var { generateEncryptionKeyPair } = require("../../lib/crypto");
    var keys = generateEncryptionKeyPair();
    fs.writeFileSync(path.join(dir, "vault.key"), JSON.stringify(keys, null, 2), { mode: 0o600 });
    var setup = runSetup(dir, { VAULT_PASSPHRASE: "pwA" });
    assert.strictEqual(setup.status, 0, setup.stderr);

    // Rotate
    var rot = runRotate(dir, { VAULT_PASSPHRASE_OLD: "pwA", VAULT_PASSPHRASE_NEW: "pwB" });
    assert.strictEqual(rot.status, 0, rot.stderr);

    // Boot with new passphrase and verify the same keypair is recovered
    var probeScript = [
      "(async () => {",
      "  var vault = require('./lib/vault');",
      "  await vault.init();",
      "  var k = vault._getKeysForTest();",
      "  console.log(JSON.stringify({ pub: k.publicKey.slice(0, 50), ec: k.ecPublicKey.slice(0, 50) }));",
      "})();",
    ].join("");
    var probe = spawnSync("node", ["-e", probeScript], {
      cwd: REPO_ROOT,
      env: Object.assign({}, process.env, {
        HERMITSTASH_DATA_DIR: dir,
        VAULT_PASSPHRASE_MODE: "required",
        VAULT_PASSPHRASE: "pwB",
        VAULT_PASSPHRASE_SOURCE: "env",
        ARGON2_FAST: "1",
      }),
      encoding: "utf8",
      timeout: 30000,
    });
    assert.strictEqual(probe.status, 0, probe.stderr);
    // Probe stdout has [vault] log lines followed by the JSON we want.
    // Grab the last non-empty line.
    var lines = probe.stdout.split(/\r?\n/).filter(function (l) { return l.trim().length > 0; });
    var recovered = JSON.parse(lines[lines.length - 1]);
    assert.ok(keys.publicKey.startsWith(recovered.pub), "publicKey prefix should match");
    assert.ok(keys.ecPublicKey.startsWith(recovered.ec), "ecPublicKey prefix should match");
  });
});
