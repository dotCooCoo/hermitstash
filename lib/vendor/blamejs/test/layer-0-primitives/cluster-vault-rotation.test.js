// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * cluster vault-key rotation acceptance.
 *
 * After a vault-key rotation (b.vault.rotate) the SHA3-512 fingerprint of
 * the vault PUBLIC keys changes on every node, but the rotation only
 * re-seals the local dataDir — the external coordination row
 * (_blamejs_cluster_state.vaultKeyFp) keeps the OLD fingerprint. Without
 * a way to declare the change legitimate, cluster.init's
 * _checkVaultKeyConsistency throws VAULT_KEY_DRIFT (FATAL) and every node
 * refuses boot.
 *
 * acceptVaultKeyRotation: true is the operator's signed-off declaration
 * "the fingerprint changed via rotation": the booting node advances the
 * canonical row to its own fingerprint and bumps a monotonic
 * rotationEpoch. expectedVaultKeyFp narrows the adoption to a single
 * blessed fingerprint. The strict cross-node drift refusal stays in force
 * whenever the rotation is NOT declared.
 *
 * These tests model "canonical is stale after a rotation" by booting once
 * (which records the LIVE fingerprint), then overwriting the row with a
 * different fingerprint — the same end-state a rotation produces, without
 * hardcoding the fingerprint domain-separation literal here (the cluster
 * module owns that; we read the live value back instead).
 *
 * Run standalone: `node test/layer-0-primitives/cluster-vault-rotation.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var fs      = require("node:fs");
var os      = require("node:os");
var path    = require("node:path");
var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;
var setupTestDb        = helpers.setupTestDb;
var teardownTestDb     = helpers.teardownTestDb;
var _makeSqliteDriver  = helpers._makeSqliteDriver;

var SECONDS = b.constants.TIME.seconds;
var BOGUS_FP = "abad1dea".repeat(16);   // 128-char lowercase hex, ≠ any live key

function _initOpts(nodeId, extra) {
  return Object.assign({
    nodeId:            nodeId,
    externalDbBackend: "ops",
    dialect:           "sqlite",
    leaseTtl:          SECONDS(30),
    heartbeatInterval: SECONDS(10),
  }, extra || {});
}

async function _setup() {
  b.cluster._resetForTest();
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-vk-rotate-"));
  var dbPath = path.join(tmpDir, "ext.db");
  var driver = _makeSqliteDriver(dbPath);
  await setupTestDb(tmpDir);            // initializes the vault
  b.externalDb.init({
    backends: { "ops": { connect: driver.connect, query: driver.query, close: driver.close } },
  });
  await b.frameworkSchema.ensureSchema({ externalDbBackend: "ops", dialect: "sqlite" });
  return {
    tmpDir: tmpDir,
    driver: driver,
    teardown: async function () {
      try { await b.cluster.shutdown(); } catch (_e) {}
      try { await b.externalDb.shutdown(); } catch (_e) {}
      driver._close();
      await teardownTestDb(tmpDir);
    },
  };
}

async function _readState() {
  var r = await b.externalDb.query(
    "SELECT vaultKeyFp, recordedByNode, rotationEpoch FROM _blamejs_cluster_state WHERE scope='state'",
    [], { backend: "ops" }
  );
  return (r.rows && r.rows[0]) || null;
}

// Record the LIVE fingerprint (first boot), then stamp the row with a
// stale fingerprint — the post-rotation canonical state.
async function _recordLiveThenStale() {
  await b.cluster.init(_initOpts("vk-seed"));
  var live = (await _readState()).vaultKeyFp;
  // shutdown() releases the DB lease so the next init can acquire; it
  // also sets the terminated flag (post-graceful-exit, isLeader stays
  // false). _resetForTest clears that flag so the SUBSEQUENT init boots
  // as a fresh process would, with isLeader reflecting the new lease.
  await b.cluster.shutdown();
  b.cluster._resetForTest();
  await b.externalDb.query(
    "UPDATE _blamejs_cluster_state SET vaultKeyFp = ?, recordedByNode = 'old-node', rotationEpoch = 7 WHERE scope='state'",
    [BOGUS_FP], { backend: "ops" }
  );
  return live;
}

function testSurface() {
  check("cluster namespace", typeof b.cluster === "object");
  check("cluster.init fn",   typeof b.cluster.init === "function");
}

async function testRotationAccepted() {
  var ctx = await _setup();
  try {
    var liveFp = await _recordLiveThenStale();
    check("seeded fingerprint is stale (≠ live)", liveFp !== BOGUS_FP);

    var threw = null;
    try { await b.cluster.init(_initOpts("vk-rotated", { acceptVaultKeyRotation: true })); }
    catch (e) { threw = e; }
    check("rotation-accept boots without VAULT_KEY_DRIFT", threw === null);
    check("rotated node holds the lease",                  b.cluster.isLeader() === true);

    var post = await _readState();
    check("canonical fingerprint advanced to live key", post.vaultKeyFp === liveFp);
    check("canonical recorded by the rotated node",     post.recordedByNode === "vk-rotated");
    check("rotation epoch bumped past the stale 7",      Number(post.rotationEpoch) === 8);
  } finally { await ctx.teardown(); }
}

async function testNoDeclarationStillRefuses() {
  // The cross-node drift case is untouched: an undeclared mismatch is
  // still FATAL so genuine drift can't silently seal unreadable columns.
  var ctx = await _setup();
  try {
    await _recordLiveThenStale();
    var threw = null;
    try { await b.cluster.init(_initOpts("vk-undeclared")); }
    catch (e) { threw = e; }
    check("undeclared mismatch throws", threw !== null);
    check("undeclared mismatch is VAULT_KEY_DRIFT", threw && threw.code === "VAULT_KEY_DRIFT");
    var post = await _readState();
    check("undeclared mismatch left the canonical row untouched", post.vaultKeyFp === BOGUS_FP);
  } finally { await ctx.teardown(); }
}

async function testExpectedFpMatchAdopts() {
  var ctx = await _setup();
  try {
    var liveFp = await _recordLiveThenStale();
    var threw = null;
    try {
      await b.cluster.init(_initOpts("vk-blessed", {
        acceptVaultKeyRotation: true,
        expectedVaultKeyFp:     liveFp,
      }));
    } catch (e) { threw = e; }
    check("blessed-fingerprint rotation adopts cleanly", threw === null);
    var post = await _readState();
    check("blessed-fingerprint canonical advanced", post.vaultKeyFp === liveFp);
  } finally { await ctx.teardown(); }
}

async function testExpectedFpMismatchRefuses() {
  // acceptVaultKeyRotation is set, but the blessed fingerprint is NOT the
  // key this node actually holds — a stale / wrong key file. Refuse.
  var ctx = await _setup();
  try {
    await _recordLiveThenStale();
    var threw = null;
    try {
      await b.cluster.init(_initOpts("vk-wrongkey", {
        acceptVaultKeyRotation: true,
        expectedVaultKeyFp:     "feedface".repeat(16),   // ≠ live, ≠ stale
      }));
    } catch (e) { threw = e; }
    check("blessed-but-wrong key throws", threw !== null);
    check("blessed-but-wrong key is VAULT_KEY_ROTATION_MISMATCH",
          threw && threw.code === "VAULT_KEY_ROTATION_MISMATCH");
    var post = await _readState();
    check("blessed-but-wrong key left the canonical row untouched", post.vaultKeyFp === BOGUS_FP);
  } finally { await ctx.teardown(); }
}

async function testSameKeyReInitIsClean() {
  // Once adopted, a fresh init with the SAME (now-canonical) key passes
  // the consistency check without declaring a rotation and without
  // bumping the epoch.
  var ctx = await _setup();
  try {
    var liveFp = await _recordLiveThenStale();
    await b.cluster.init(_initOpts("vk-adopt", { acceptVaultKeyRotation: true }));
    var epochAfterAdopt = Number((await _readState()).rotationEpoch);
    await b.cluster.shutdown();

    var threw = null;
    try { await b.cluster.init(_initOpts("vk-rejoin")); }
    catch (e) { threw = e; }
    check("re-init on the adopted key needs no rotation declaration", threw === null);
    var post = await _readState();
    check("re-init left fingerprint at the live key", post.vaultKeyFp === liveFp);
    check("re-init did NOT bump the epoch", Number(post.rotationEpoch) === epochAfterAdopt);
  } finally { await ctx.teardown(); }
}

async function testConfigValidation() {
  var ctx = await _setup();
  try {
    var t1 = null;
    try { await b.cluster.init(_initOpts("vk-cfg1", { acceptVaultKeyRotation: "yes" })); }
    catch (e) { t1 = e; }
    check("non-boolean acceptVaultKeyRotation throws", t1 && t1.code === "INVALID_CONFIG");

    b.cluster._resetForTest();
    var t2 = null;
    try { await b.cluster.init(_initOpts("vk-cfg2", { expectedVaultKeyFp: "not-hex" })); }
    catch (e) { t2 = e; }
    check("non-hex expectedVaultKeyFp throws", t2 && t2.code === "INVALID_CONFIG");

    b.cluster._resetForTest();
    var t3 = null;
    try { await b.cluster.init(_initOpts("vk-cfg3", { expectedVaultKeyFp: BOGUS_FP })); }
    catch (e) { t3 = e; }
    check("expectedVaultKeyFp without acceptVaultKeyRotation throws", t3 && t3.code === "INVALID_CONFIG");
  } finally { await ctx.teardown(); }
}

async function run() {
  testSurface();
  await testRotationAccepted();
  await testNoDeclarationStillRefuses();
  await testExpectedFpMatchAdopts();
  await testExpectedFpMismatchRefuses();
  await testSameKeyReInitIsClean();
  await testConfigValidation();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[cluster-vault-rotation] OK — " + helpers.getChecks() + " checks passed"); },
    // Rethrow rather than console.error(e): setupTestDb seeds a vault
    // passphrase, and logging the error object trips CodeQL's clear-text-
    // logging taint. Let Node print the uncaught error + stack and exit
    // non-zero, with no logging sink for the taint to reach.
    function (e) { process.exitCode = 1; throw e; }
  );
}
