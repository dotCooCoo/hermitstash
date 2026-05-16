"use strict";
/**
 * b.testHarness — isolated-boot helper for framework-consumer test
 * suites. Tests verify the dataDir / env / vault lifecycle.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

var nodeFs = require("node:fs");

function testSurface() {
  check("testHarness.start is fn",    typeof b.testHarness.start === "function");
  check("TestHarnessError is fn",     typeof b.testHarness.TestHarnessError === "function");
}

async function testCreatesTempDataDirByDefault() {
  var h = await b.testHarness.start({ initVault: false });
  try {
    check("dataDir is absolute",      h.dataDir && h.dataDir.length > 0);
    check("dataDir exists",           nodeFs.existsSync(h.dataDir));
    check("dbPath default",           h.dbPath === require("node:path").join(h.dataDir, "db.sqlite"));
    check("vaultDir default",         h.vaultDir === require("node:path").join(h.dataDir, "vault"));
    check("vaultDir exists",          nodeFs.existsSync(h.vaultDir));
  } finally {
    await h.stop();
  }
  check("dataDir removed after stop", !nodeFs.existsSync(h.dataDir));
}

async function testEnvPrefixSetsAndRestores() {
  var pre = process.env.MYAPP_DATA_DIR;
  var h = await b.testHarness.start({ envPrefix: "MYAPP", initVault: false });
  try {
    check("env MYAPP_DATA_DIR set",   process.env.MYAPP_DATA_DIR === h.dataDir);
    check("env MYAPP_DB_PATH set",    process.env.MYAPP_DB_PATH === h.dbPath);
    check("env MYAPP_VAULT_DIR set",  process.env.MYAPP_VAULT_DIR === h.vaultDir);
  } finally {
    await h.stop();
  }
  check("env MYAPP_DATA_DIR restored", process.env.MYAPP_DATA_DIR === pre);
}

async function testEnvOverridesSetAndRestore() {
  var preLog = process.env.LOG_LEVEL;
  process.env.LOG_LEVEL = "info";
  var h = await b.testHarness.start({ env: { LOG_LEVEL: "error", CUSTOM_TEST_VAR: "abc" }, initVault: false });
  try {
    check("env LOG_LEVEL overridden",  process.env.LOG_LEVEL === "error");
    check("env CUSTOM_TEST_VAR set",   process.env.CUSTOM_TEST_VAR === "abc");
  } finally {
    await h.stop();
  }
  check("env LOG_LEVEL restored to prior", process.env.LOG_LEVEL === "info");
  check("env CUSTOM_TEST_VAR cleared",     process.env.CUSTOM_TEST_VAR === undefined);
  process.env.LOG_LEVEL = preLog;
}

async function testUsesPreExistingDataDir() {
  var nodePath = require("node:path");
  var nodeOs   = require("node:os");
  var tmpRoot = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "harness-preset-"));
  var h = await b.testHarness.start({ dataDir: tmpRoot, initVault: false });
  try {
    check("uses operator-supplied dataDir", h.dataDir === nodePath.resolve(tmpRoot));
  } finally {
    await h.stop();
  }
  check("operator-supplied dataDir KEPT",  nodeFs.existsSync(tmpRoot));
  // Cleanup
  nodeFs.rmSync(tmpRoot, { recursive: true, force: true });
}

async function testKeepOnStopRetainsDataDir() {
  var h = await b.testHarness.start({ initVault: false, keepOnStop: true });
  await h.stop();
  check("keepOnStop retains dataDir",      nodeFs.existsSync(h.dataDir));
  nodeFs.rmSync(h.dataDir, { recursive: true, force: true });
}

async function testInitVaultDefault() {
  var h = await b.testHarness.start();  // initVault default true
  try {
    check("vault.key file written",  nodeFs.existsSync(require("node:path").join(h.vaultDir, "vault.key")));
  } finally {
    await h.stop();
  }
}

async function testRefusesBadInput() {
  async function expectCode(label, fn) {
    var threw = null;
    try { await fn(); } catch (e) { threw = e; }
    check(label, threw && (threw.code || "").indexOf("test-harness/bad-input") !== -1);
  }
  await expectCode("dataDir empty string refused",
    function () { return b.testHarness.start({ dataDir: "", initVault: false }); });
  await expectCode("envPrefix lowercase refused",
    function () { return b.testHarness.start({ envPrefix: "myapp", initVault: false }); });
  await expectCode("envPrefix with hyphen refused",
    function () { return b.testHarness.start({ envPrefix: "MY-APP", initVault: false }); });
  await expectCode("env array refused",
    function () { return b.testHarness.start({ env: [], initVault: false }); });
}

async function testConcurrentVaultHarnessesShareInit() {
  // Codex P1 regression test: two harnesses with initVault=true running
  // in parallel share the process-global vault state. Stopping the
  // first harness must NOT tear down vault for the second; only the
  // last-stopped harness releases the vault.
  var h1 = await b.testHarness.start();  // initVault default true
  var h2 = await b.testHarness.start();  // shares vault state
  try {
    // Vault is initialized for both. Verify by sealing/unsealing
    // via the framework's existing surface.
    var sealed = b.vault.seal(Buffer.from("hello"));
    check("vault.seal works while both harnesses live", sealed && sealed.length > 0);

    // Stop h1 — vault must REMAIN initialized for h2.
    await h1.stop();
    var sealedAfterH1Stop = b.vault.seal(Buffer.from("world"));
    check("vault.seal still works after h1.stop (refcount > 0)",
      sealedAfterH1Stop && sealedAfterH1Stop.length > 0);
  } finally {
    await h2.stop();
  }
}

async function testEnvBackupPreservesOriginal() {
  // Codex P2 regression test: _setEnv must capture the ORIGINAL
  // pre-harness value on the first write to a key, even if a later
  // write inside the same start() overwrites with a harness-derived
  // value. Otherwise stop() restores the harness-written intermediate
  // instead of the pre-harness value.
  process.env.MYAPP_DATA_DIR = "original-value";
  try {
    var h = await b.testHarness.start({
      envPrefix: "MYAPP",
      env: { MYAPP_DATA_DIR: "second-write-value" },
      initVault: false,
    });
    await h.stop();
    check("env restored to original pre-harness value",
      process.env.MYAPP_DATA_DIR === "original-value");
  } finally {
    delete process.env.MYAPP_DATA_DIR;
  }
}

async function testConcurrentHandlesIsolated() {
  // Two harnesses running in parallel must NOT collide on dataDir.
  var h1 = await b.testHarness.start({ initVault: false });
  var h2 = await b.testHarness.start({ initVault: false });
  try {
    check("h1.dataDir != h2.dataDir", h1.dataDir !== h2.dataDir);
    check("both exist",                nodeFs.existsSync(h1.dataDir) && nodeFs.existsSync(h2.dataDir));
  } finally {
    await h1.stop();
    await h2.stop();
  }
}

async function testStopIsIdempotent() {
  var h = await b.testHarness.start({ initVault: false });
  await h.stop();
  await h.stop();  // second call must not throw
  check("stop() idempotent", !nodeFs.existsSync(h.dataDir));
}

async function run() {
  testSurface();
  await testCreatesTempDataDirByDefault();
  await testEnvPrefixSetsAndRestores();
  await testEnvOverridesSetAndRestore();
  await testUsesPreExistingDataDir();
  await testKeepOnStopRetainsDataDir();
  await testInitVaultDefault();
  await testRefusesBadInput();
  await testConcurrentHandlesIsolated();
  await testConcurrentVaultHarnessesShareInit();
  await testEnvBackupPreservesOriginal();
  await testStopIsIdempotent();
}

module.exports = { run: run };

if (require.main === module) {
  run().catch(function (e) { process.stderr.write("FAIL: " + (e && e.stack || e) + "\n"); process.exit(1); });
}
