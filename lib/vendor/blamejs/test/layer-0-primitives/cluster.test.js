// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * cluster — leader election + write-side gates.
 *
 * Covers b.cluster.externalDbBackend (the wired shared-DB handle getter)
 * and b.cluster.onTransition (role-transition callback registration +
 * firing) on the happy path, plus the full error / adversarial /
 * defensive surface:
 *
 *   - b.cluster.init config-time rejections (missing nodeId, sub-minimum
 *     lease/heartbeat, heartbeat >= lease, bad role, rejected endpoint,
 *     malformed expectedVaultKeyFp, un-declared rotation blessing,
 *     non-boolean acceptVaultKeyRotation, no provider/backend, double
 *     init).
 *   - The heartbeat state machine driven through a controllable custom
 *     election provider: acquire failure, renew success, LEASE_LOST
 *     takeover, transient renew error, follower re-acquisition.
 *   - b.cluster.currentLeader + b.cluster.discoveryHandler across the
 *     single-node fallback, a live leader, no-leader, and provider-error
 *     paths.
 *   - Boot-time chain-tip rollback detection (counter regression,
 *     row-hash substitution, non-missing-table re-throw, empty-tip skip,
 *     consistent-chain pass) against a live in-process SQLite backend.
 *   - Vault-key consistency: cross-node drift refusal, rotation-blessing
 *     mismatch, rotation adoption, the fail-closed CLUSTER_STATE_MISSING
 *     and concurrent-divergent-adopt guards, the structured
 *     missing-relation code/errno classification, and the vault-not-
 *     initialized gates-only skip.
 *
 * Run standalone: `node test/layer-0-primitives/cluster.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b                 = helpers.b;
var fs                = helpers.fs;
var os                = helpers.os;
var path              = helpers.path;
var check             = helpers.check;
var setupTestDb       = helpers.setupTestDb;
var teardownTestDb    = helpers.teardownTestDb;
var _makeSqliteDriver = helpers._makeSqliteDriver;
var _mockReq          = helpers._mockReq;
var _mockRes          = helpers._mockRes;
var C                 = b.constants;

// ---- shared test doubles ----

// A controllable leader-election provider. cluster.init accepts a custom
// `provider` (a documented opt), so this drives the real heartbeat state
// machine in-process with zero DB dependency — every acquire / renew /
// release / currentLeader outcome is scripted through `ctl`.
function _makeStubProvider() {
  var ctl = {
    acquireResult:       "lease",  // "lease" | null | "throw"
    renewMode:           "ok",     // "ok" | "lost" | "transient"
    releaseMode:         "ok",     // "ok" | "throw"
    currentLeaderResult: null,     // object | null | "throw"
    fencing:             0,
    ensureSchemaCalls:   0,
  };
  var provider = {
    ensureSchema: async function () { ctl.ensureSchemaCalls += 1; },
    acquireLease: async function (nodeId, ttlMs, opts) {
      if (ctl.acquireResult === "throw") throw new Error("stub acquire boom");
      if (ctl.acquireResult === null) return null;
      ctl.fencing += 1;
      return {
        nodeId:       nodeId,
        leaseId:      "lease-" + ctl.fencing,
        acquiredAt:   Date.now(),
        expiresAt:    Date.now() + ttlMs,
        fencingToken: ctl.fencing,
        endpoint:     (opts && opts.endpoint) || null,
      };
    },
    renewLease: async function (lease, opts) {
      if (ctl.renewMode === "lost") {
        var e = new Error("stub lease taken over");
        e.code = "LEASE_LOST";
        throw e;
      }
      if (ctl.renewMode === "transient") throw new Error("stub transient renew boom");
      return Object.assign({}, lease, {
        expiresAt: Date.now() + C.TIME.seconds(30),
        endpoint:  (opts && "endpoint" in opts) ? opts.endpoint : (lease.endpoint || null),
      });
    },
    releaseLease: async function () {
      if (ctl.releaseMode === "throw") throw new Error("stub release boom");
    },
    currentLeader: async function () {
      if (ctl.currentLeaderResult === "throw") throw new Error("stub currentLeader boom");
      return ctl.currentLeaderResult;
    },
  };
  return { provider: provider, ctl: ctl };
}

// Execute one raw statement against the in-process SQLite coordination DB
// through the same driver handle cluster.js queries, so a seeded tip /
// state row is visible to the boot-time checks.
async function _seed(driver, sqlText, params) {
  var client = await driver.connect();
  return driver.query(client, sqlText, params || []);
}

// Live SQLite coordination fixture: real vault (needed for the vault-key
// fingerprint) + a real external-db backend the boot-time checks run
// against. A stub election provider keeps the node a pinned follower so
// no lease-election writes get in the way of the check being exercised.
async function _coordFixture() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cluster-cov-"));
  b.cluster._resetForTest();
  await setupTestDb(tmpDir);
  var dbPath = path.join(tmpDir, "ha-coord.db");
  var driver = _makeSqliteDriver(dbPath);
  b.externalDb.init({
    backends: { ops: { connect: driver.connect, query: driver.query, close: driver.close } },
  });
  return {
    tmpDir: tmpDir,
    driver: driver,
    teardown: async function () {
      try { await b.cluster.shutdown(); } catch (_e) { /* idempotent */ }
      try { await b.externalDb.shutdown(); } catch (_e) { /* best-effort */ }
      try { driver._close(); } catch (_e) { /* best-effort */ }
      await teardownTestDb(tmpDir);
    },
  };
}

// Init as a pinned follower against a custom backend/provider pair, so the
// boot-time rollback + vault-key checks run but no leader election fires.
async function _initFollowerAgainst(backendName, provider) {
  await b.cluster.init({
    nodeId:            "cov-follower",
    role:              "follower",
    provider:          provider,
    externalDbBackend: backendName,
    dialect:           "sqlite",
    leaseTtl:          C.TIME.seconds(30),
    heartbeatInterval: C.TIME.seconds(15),
  });
}

// A 128-char lowercase-hex string (a well-formed SHA3-512 fingerprint
// shape) that is not this node's real vault-key fingerprint.
function _bogusFp(ch) { return String(ch).repeat(128); }

// ---- existing coverage: getter + transition happy path ----

async function testExternalDbBackendAndOnTransition() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cluster-"));
  b.cluster._resetForTest();
  await setupTestDb(tmpDir);

  var dbPath = path.join(tmpDir, "ha-coord.db");
  var driver = _makeSqliteDriver(dbPath);
  b.externalDb.init({
    backends: {
      ops: { connect: driver.connect, query: driver.query, close: driver.close },
    },
  });

  var events = [];
  var order  = [];
  try {
    // Pre-init contract: nothing wired yet.
    check("cluster.externalDbBackend null before init", b.cluster.externalDbBackend() === null);
    check("cluster.isClusterMode false before init",    b.cluster.isClusterMode() === false);

    // Config-time tier: a non-function handler throws synchronously.
    var badThrew = null;
    try { b.cluster.onTransition("not-a-fn"); } catch (e) { badThrew = e; }
    check("cluster.onTransition rejects a non-function handler",
          badThrew && badThrew.code === "INVALID_HANDLER");

    // Register two handlers BEFORE init; both must fire in registration order.
    b.cluster.onTransition(function (ev) { order.push("a"); events.push(ev); });
    b.cluster.onTransition(function (ev) { order.push("b"); });

    await b.cluster.init({
      nodeId:            "cluster-domain-node",
      externalDbBackend: "ops",
      dialect:           "sqlite",
      leaseTtl:          C.TIME.seconds(30),
      heartbeatInterval: C.TIME.seconds(10),
    });

    // externalDbBackend now returns the wired handle name.
    check("cluster.externalDbBackend returns the configured backend after init",
          b.cluster.externalDbBackend() === "ops");
    check("cluster.isClusterMode true once wired", b.cluster.isClusterMode() === true);

    // Single node → immediate leader → a lease-acquired transition fired.
    await helpers.waitUntil(function () {
      return events.some(function (e) { return e.kind === "lease-acquired"; });
    }, { timeoutMs: 5000, label: "cluster.onTransition: lease-acquired fired" });
    var acq = events.find(function (e) { return e.kind === "lease-acquired"; });
    check("transition event carries the nodeId",       acq.nodeId === "cluster-domain-node");
    check("transition event carries a numeric fencingToken",
          typeof acq.fencingToken === "number" && acq.fencingToken >= 1);
    check("transition event carries a timestamp",      typeof acq.at === "number");
    check("both handlers ran, in registration order",
          order.length >= 2 && order[0] === "a" && order[1] === "b");

    // shutdown releases the lease + emits a lease-released transition.
    await b.cluster.shutdown();
    await helpers.waitUntil(function () {
      return events.some(function (e) { return e.kind === "lease-released"; });
    }, { timeoutMs: 5000, label: "cluster.onTransition: lease-released fired" });
    check("cluster.externalDbBackend null again after shutdown",
          b.cluster.externalDbBackend() === null);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) { /* idempotent */ }
    try { await b.externalDb.shutdown(); } catch (_e) { /* best-effort */ }
    try { driver._close(); } catch (_e) { /* best-effort */ }
    await teardownTestDb(tmpDir);
  }
}

// ---- init config-time validation (THROW tier) ----

async function _expectInitThrow(label, opts, expectedCode) {
  b.cluster._resetForTest();
  var threw = null;
  try { await b.cluster.init(opts); } catch (e) { threw = e; }
  check(label + " throws", threw !== null);
  check(label + " code=" + expectedCode, threw && threw.code === expectedCode);
  b.cluster._resetForTest();
}

async function testInitConfigValidation() {
  // Missing nodeId (explicit empty opts, and the no-argument form).
  await _expectInitThrow("init without nodeId", {}, "INVALID_CONFIG");
  await _expectInitThrow("init with no opts object", undefined, "INVALID_CONFIG");

  // leaseTtl below the 10s floor.
  await _expectInitThrow("init leaseTtl below floor",
    { nodeId: "n", leaseTtl: C.TIME.seconds(5), externalDbBackend: "x" }, "INVALID_TTL");

  // heartbeat below the 1s floor.
  await _expectInitThrow("init heartbeat below floor",
    { nodeId: "n", heartbeatInterval: 500, externalDbBackend: "x" }, "INVALID_HEARTBEAT");

  // heartbeat >= leaseTtl (must fit comfortably inside the lease).
  await _expectInitThrow("init heartbeat >= leaseTtl",
    { nodeId: "n", leaseTtl: C.TIME.seconds(10), heartbeatInterval: C.TIME.seconds(10),
      externalDbBackend: "x" }, "INVALID_HEARTBEAT");

  // Role outside leader/follower.
  await _expectInitThrow("init with unknown role",
    { nodeId: "n", role: "observer", externalDbBackend: "x" }, "INVALID_ROLE");

  // Endpoint rejected — cleartext HTTP under the HTTPS-only default.
  await _expectInitThrow("init with non-TLS endpoint",
    { nodeId: "n", endpoint: "http://plain.internal:8080", externalDbBackend: "x" },
    "INVALID_ENDPOINT");

  // expectedVaultKeyFp that isn't a 128-char lowercase-hex fingerprint.
  await _expectInitThrow("init with malformed expectedVaultKeyFp",
    { nodeId: "n", acceptVaultKeyRotation: true, expectedVaultKeyFp: "not-a-fingerprint",
      externalDbBackend: "x" }, "INVALID_CONFIG");

  // expectedVaultKeyFp blessed but rotation acceptance never enabled.
  await _expectInitThrow("init blessing a fingerprint without acceptVaultKeyRotation",
    { nodeId: "n", expectedVaultKeyFp: _bogusFp("a"), externalDbBackend: "x" },
    "INVALID_CONFIG");

  // Non-boolean acceptVaultKeyRotation.
  await _expectInitThrow("init with non-boolean acceptVaultKeyRotation",
    { nodeId: "n", acceptVaultKeyRotation: "yes", externalDbBackend: "x" }, "INVALID_CONFIG");

  // Neither a custom provider nor an externalDbBackend.
  await _expectInitThrow("init without provider or externalDbBackend",
    { nodeId: "n" }, "INVALID_CONFIG");

  // Double init — second call refused.
  b.cluster._resetForTest();
  var s = _makeStubProvider();
  var doubleThrew = null;
  try {
    await b.cluster.init({
      nodeId: "double-node", provider: s.provider, role: "follower",
      leaseTtl: C.TIME.seconds(30), heartbeatInterval: C.TIME.seconds(15),
    });
    try {
      await b.cluster.init({ nodeId: "double-node-2", provider: s.provider, role: "follower" });
    } catch (e) { doubleThrew = e; }
    check("second cluster.init is refused", doubleThrew && doubleThrew.code === "ALREADY_INITIALIZED");
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) { /* idempotent */ }
    b.cluster._resetForTest();
  }
}

// ---- sync surface: getters, requireLeader, endpoint validation, reset ----

async function testSyncSurfaceAndGetters() {
  b.cluster._resetForTest();

  // Permanent-leader fallback before init.
  check("isLeader true before init (permanent-leader fallback)", b.cluster.isLeader() === true);
  check("currentNodeId single-node before init",
        b.cluster.currentNodeId() === "single-node-local");
  check("fencingToken 0 before init", b.cluster.fencingToken() === 0);
  check("dialect null before init", b.cluster.dialect() === null);
  // NotLeaderError with no message falls back to its default text.
  var defErr = new b.cluster.NotLeaderError();
  check("NotLeaderError default message", /not leader/.test(defErr.message));
  check("endpoint null before init", b.cluster.endpoint() === null);
  var preThrew = null;
  try { b.cluster.requireLeader(); } catch (e) { preThrew = e; }
  check("requireLeader does not throw before init", preThrew === null);

  var s = _makeStubProvider();
  s.ctl.acquireResult = "lease";
  var transitions = [];
  try {
    await b.cluster.init({
      nodeId:            "getter-node",
      role:              "leader",
      provider:          s.provider,
      dialect:           "postgres",
      endpoint:          "https://getter.internal:8443",
      leaseTtl:          C.TIME.seconds(30),
      heartbeatInterval: C.TIME.seconds(15),
      onTransition:      function (ev) { transitions.push(ev); },
    });

    check("isLeader true after acquiring a lease", b.cluster.isLeader() === true);
    check("fencingToken reflects the lease token", b.cluster.fencingToken() >= 1);
    check("dialect returns the configured dialect", b.cluster.dialect() === "postgres");
    check("endpoint returns the validated endpoint",
          b.cluster.endpoint() === "https://getter.internal:8443");
    check("onTransition supplied at init fired on acquire",
          transitions.some(function (e) { return e.kind === "lease-acquired"; }));

    // requireLeader passes while leader.
    var leaderThrew = null;
    try { b.cluster.requireLeader(); } catch (e) { leaderThrew = e; }
    check("requireLeader passes while holding the lease", leaderThrew === null);

    // shutdown → terminated: never leader again until a fresh init.
    await b.cluster.shutdown();
    check("isLeader false after shutdown (terminated)", b.cluster.isLeader() === false);
    var postThrew = null;
    try { b.cluster.requireLeader(); } catch (e) { postThrew = e; }
    check("requireLeader throws NotLeaderError after shutdown",
          postThrew instanceof b.cluster.NotLeaderError);
    check("post-shutdown NotLeaderError notes the uninitialized state",
          postThrew && /not initialized/.test(postThrew.message));
    check("NotLeaderError carries a 503 status", postThrew && postThrew.statusCode === 503);
    check("NotLeaderError carries the cluster/not-leader flags",
          postThrew && postThrew.code === "NOT_LEADER" &&
          postThrew.isNotLeaderError === true && postThrew.isClusterError === true);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) { /* idempotent */ }
    b.cluster._resetForTest();
  }

  // Follower: initialized but never holds the lease → requireLeader throws
  // WITHOUT the "(cluster not initialized)" suffix.
  b.cluster._resetForTest();
  var f = _makeStubProvider();
  try {
    await b.cluster.init({
      nodeId: "follower-node", role: "follower", provider: f.provider,
      leaseTtl: C.TIME.seconds(30), heartbeatInterval: C.TIME.seconds(15),
    });
    check("follower is not leader", b.cluster.isLeader() === false);
    var fThrew = null;
    try { b.cluster.requireLeader(); } catch (e) { fThrew = e; }
    check("follower requireLeader throws NOT_LEADER", fThrew && fThrew.code === "NOT_LEADER");
    check("follower NotLeaderError omits the uninitialized suffix",
          fThrew && !/not initialized/.test(fThrew.message));

    // _resetForTest with a running heartbeat timer stops it cleanly.
    b.cluster._resetForTest();
    check("reset clears cluster mode", b.cluster.isClusterMode() === false);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) { /* idempotent */ }
    b.cluster._resetForTest();
  }

  // Endpoint opt-out: cleartext accepted when allowedProtocols permits it.
  b.cluster._resetForTest();
  var h = _makeStubProvider();
  try {
    await b.cluster.init({
      nodeId: "cleartext-node", role: "follower", provider: h.provider,
      endpoint: "http://internal.cleartext:8080",
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      leaseTtl: C.TIME.seconds(30), heartbeatInterval: C.TIME.seconds(15),
    });
    check("cleartext endpoint accepted under ALLOW_HTTP_ALL",
          b.cluster.endpoint() === "http://internal.cleartext:8080");
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) { /* idempotent */ }
    b.cluster._resetForTest();
  }
}

// ---- heartbeat state machine ----

async function testHeartbeatStateMachine() {
  // (1) Acquire failure at init is caught — node stays a non-leader and
  //     init still completes.
  b.cluster._resetForTest();
  var s1 = _makeStubProvider();
  s1.ctl.acquireResult = "throw";
  try {
    await b.cluster.init({
      nodeId: "hb-acq-fail", role: "leader", provider: s1.provider,
      leaseTtl: C.TIME.seconds(30), heartbeatInterval: C.TIME.seconds(15),
    });
    check("acquire failure leaves the node non-leader", b.cluster.isLeader() === false);
    check("acquire failure still completes init", b.cluster.isClusterMode() === false);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) { /* idempotent */ }
    b.cluster._resetForTest();
  }

  // (2) Renew success on the next heartbeat keeps the lease.
  b.cluster._resetForTest();
  var s2 = _makeStubProvider();
  s2.ctl.acquireResult = "lease";
  try {
    await b.cluster.init({
      nodeId: "hb-renew", role: "leader", provider: s2.provider,
      leaseTtl: C.TIME.seconds(30), heartbeatInterval: C.TIME.seconds(15),
    });
    check("holds lease after initial acquire", b.cluster.isLeader() === true);
    var tokenBefore = b.cluster.fencingToken();
    await b.cluster._heartbeatNowForTest();
    check("renew keeps the node leader", b.cluster.isLeader() === true);
    check("renew does not bump the fencing token", b.cluster.fencingToken() === tokenBefore);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) { /* idempotent */ }
    b.cluster._resetForTest();
  }

  // (3) LEASE_LOST on renew → step down to follower + emit lease-lost.
  b.cluster._resetForTest();
  var s3 = _makeStubProvider();
  s3.ctl.acquireResult = "lease";
  var lostEvents = [];
  try {
    await b.cluster.init({
      nodeId: "hb-lost", role: "leader", provider: s3.provider,
      leaseTtl: C.TIME.seconds(30), heartbeatInterval: C.TIME.seconds(15),
      onTransition: function (ev) { lostEvents.push(ev); },
    });
    check("leader before lease loss", b.cluster.isLeader() === true);
    s3.ctl.renewMode = "lost";
    await b.cluster._heartbeatNowForTest();
    check("lease loss steps the node down", b.cluster.isLeader() === false);
    check("lease loss emits a lease-lost transition",
          lostEvents.some(function (e) { return e.kind === "lease-lost"; }));
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) { /* idempotent */ }
    b.cluster._resetForTest();
  }

  // (4) Transient renew error → lease preserved, retry next tick.
  b.cluster._resetForTest();
  var s4 = _makeStubProvider();
  s4.ctl.acquireResult = "lease";
  try {
    await b.cluster.init({
      nodeId: "hb-transient", role: "leader", provider: s4.provider,
      leaseTtl: C.TIME.seconds(30), heartbeatInterval: C.TIME.seconds(15),
    });
    s4.ctl.renewMode = "transient";
    await b.cluster._heartbeatNowForTest();
    check("transient renew error preserves the lease", b.cluster.isLeader() === true);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) { /* idempotent */ }
    b.cluster._resetForTest();
  }

  // (5) Follower re-acquisition path: no lease yet → heartbeat retries the
  //     acquire (jitter branch), succeeds, becomes leader.
  b.cluster._resetForTest();
  var s5 = _makeStubProvider();
  s5.ctl.acquireResult = null;                 // initial acquire yields nothing
  try {
    await b.cluster.init({
      nodeId: "hb-reacquire", role: "leader", provider: s5.provider,
      leaseTtl: C.TIME.seconds(30), heartbeatInterval: C.TIME.seconds(1),
    });
    check("no lease after a null initial acquire", b.cluster.isLeader() === false);
    s5.ctl.acquireResult = "lease";
    await b.cluster._heartbeatNowForTest();     // !lease → jitter → re-acquire
    check("heartbeat re-acquisition promotes the node", b.cluster.isLeader() === true);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) { /* idempotent */ }
    b.cluster._resetForTest();
  }

  // (5b) A throwing releaseLease on shutdown is caught — shutdown still
  //      completes and the node steps down.
  b.cluster._resetForTest();
  var s5b = _makeStubProvider();
  s5b.ctl.acquireResult = "lease";
  s5b.ctl.releaseMode   = "throw";
  await b.cluster.init({
    nodeId: "hb-release-throws", role: "leader", provider: s5b.provider,
    leaseTtl: C.TIME.seconds(30), heartbeatInterval: C.TIME.seconds(15),
  });
  check("leader before a throwing-release shutdown", b.cluster.isLeader() === true);
  var releaseThrew = null;
  try { await b.cluster.shutdown(); } catch (e) { releaseThrew = e; }
  check("shutdown swallows a releaseLease failure", releaseThrew === null);
  check("node is not leader after a throwing-release shutdown", b.cluster.isLeader() === false);
  b.cluster._resetForTest();

  // (5c) A pinned follower's heartbeat never claims the lease.
  b.cluster._resetForTest();
  var s5c = _makeStubProvider();
  s5c.ctl.acquireResult = "lease";           // would succeed IF a follower asked
  try {
    await b.cluster.init({
      nodeId: "hb-follower", role: "follower", provider: s5c.provider,
      leaseTtl: C.TIME.seconds(30), heartbeatInterval: C.TIME.seconds(1),
    });
    check("initialized follower reports fencingToken 0", b.cluster.fencingToken() === 0);
    await b.cluster._heartbeatNowForTest();   // !lease → jitter → _tryAcquire → follower no-op
    check("a follower heartbeat does not claim the lease", b.cluster.isLeader() === false);
    check("no acquire is attempted for a pinned follower", s5c.ctl.fencing === 0);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) { /* idempotent */ }
    b.cluster._resetForTest();
  }

  // (6) Heartbeat after shutdown is a no-op (guarded on !initialized).
  b.cluster._resetForTest();
  var s6 = _makeStubProvider();
  await b.cluster.init({
    nodeId: "hb-after-shutdown", role: "follower", provider: s6.provider,
    leaseTtl: C.TIME.seconds(30), heartbeatInterval: C.TIME.seconds(15),
  });
  await b.cluster.shutdown();
  var afterShutdownThrew = null;
  try { await b.cluster._heartbeatNowForTest(); } catch (e) { afterShutdownThrew = e; }
  check("heartbeat after shutdown is a no-op", afterShutdownThrew === null);
  b.cluster._resetForTest();

  // (7) A throwing transition handler is isolated — the next handler runs.
  b.cluster._resetForTest();
  var s7 = _makeStubProvider();
  s7.ctl.acquireResult = "lease";
  var goodRan = false;
  try {
    await b.cluster.init({
      nodeId: "hb-throwing-handler", role: "leader", provider: s7.provider,
      leaseTtl: C.TIME.seconds(30), heartbeatInterval: C.TIME.seconds(15),
      onTransition: function () { throw new Error("handler boom"); },
    });
    b.cluster.onTransition(function () { goodRan = true; });
    // Force a fresh acquire transition via a lease-lost / re-acquire cycle.
    s7.ctl.renewMode = "lost";
    await b.cluster._heartbeatNowForTest();     // lease-lost (both handlers)
    s7.ctl.renewMode = "ok";
    await b.cluster._heartbeatNowForTest();     // re-acquire → lease-acquired
    check("a throwing transition handler does not break the chain", goodRan === true);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) { /* idempotent */ }
    b.cluster._resetForTest();
  }
}

// ---- currentLeader + discoveryHandler ----

async function _invokeDiscovery() {
  var handler = b.cluster.discoveryHandler();
  var req = _mockReq("GET", "/cluster/leader");
  var res = _mockRes();
  await handler(req, res);
  var cap = res._captured();
  return { status: cap.status, body: cap.body ? JSON.parse(cap.body) : null, headers: cap.headers };
}

async function testCurrentLeaderAndDiscovery() {
  // Single-node fallback (init never called): synthetic leader record.
  b.cluster._resetForTest();
  var single = await b.cluster.currentLeader();
  check("currentLeader single-node nodeId", single.nodeId === "single-node-local");
  check("currentLeader single-node lease never expires", single.leaseExpiresAt === Infinity);
  check("currentLeader single-node fencingToken 0", single.fencingToken === 0);

  var d0 = await _invokeDiscovery();
  check("discovery single-node replies 200", d0.status === 200);
  check("discovery single-node reports the synthetic leader",
        d0.body && d0.body.leader && d0.body.leader.nodeId === "single-node-local");
  check("discovery emits Cache-Control: no-store",
        d0.headers && d0.headers["cache-control"] === "no-store");

  // Live leader through the provider.
  b.cluster._resetForTest();
  var s = _makeStubProvider();
  s.ctl.acquireResult = "lease";
  try {
    await b.cluster.init({
      nodeId: "disco-node", role: "leader", provider: s.provider,
      endpoint: "https://disco.internal:8443",
      leaseTtl: C.TIME.seconds(30), heartbeatInterval: C.TIME.seconds(15),
    });

    s.ctl.currentLeaderResult = {
      nodeId: "disco-node", leaseExpiresAt: Date.now() + C.TIME.seconds(30),
      fencingToken: 7, endpoint: "https://disco.internal:8443",
    };
    var leader = await b.cluster.currentLeader();
    check("currentLeader returns the provider snapshot", leader && leader.nodeId === "disco-node");

    var dLeader = await _invokeDiscovery();
    check("discovery with a live leader replies 200", dLeader.status === 200);
    check("discovery echoes the leader nodeId",
          dLeader.body.leader && dLeader.body.leader.nodeId === "disco-node");
    check("discovery self block reflects this node",
          dLeader.body.self && dLeader.body.self.nodeId === "disco-node" &&
          dLeader.body.self.isLeader === true);

    // No leader (election in progress / DB has no live row).
    s.ctl.currentLeaderResult = null;
    var dNone = await _invokeDiscovery();
    check("discovery with no leader replies 503", dNone.status === 503);
    check("discovery no-leader body carries a null leader", dNone.body.leader === null);

    // Provider error → generic 503, no internal detail echoed.
    s.ctl.currentLeaderResult = "throw";
    var dErr = await _invokeDiscovery();
    check("discovery on provider error replies 503", dErr.status === 503);
    check("discovery error body uses a generic reason",
          dErr.body.error === "leader lookup unavailable");
    check("discovery error body does not echo the internal message",
          !/boom/.test(JSON.stringify(dErr.body)));
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) { /* idempotent */ }
    b.cluster._resetForTest();
  }
}

// ---- boot-time chain-tip rollback detection ----

async function testChainTipRollback() {
  // Counter regression → FATAL rollback refusal.
  var fx1 = await _coordFixture();
  try {
    await _seed(fx1.driver,
      "CREATE TABLE _blamejs_audit_tip (scope TEXT, atMonotonicCounter INTEGER, rowHash TEXT)");
    await _seed(fx1.driver, "CREATE TABLE _blamejs_audit_log (monotonicCounter INTEGER, rowHash TEXT)");
    await _seed(fx1.driver,
      "INSERT INTO _blamejs_audit_tip (scope, atMonotonicCounter, rowHash) VALUES ('audit', 100, NULL)");
    var s = _makeStubProvider();
    var threw = null;
    try { await _initFollowerAgainst("ops", s.provider); } catch (e) { threw = e; }
    check("counter regression refuses boot", threw && threw.code === "ROLLBACK_DETECTED");
    check("counter regression message names the audit chain",
          threw && /audit-log rollback/.test(threw.message));
  } finally {
    await fx1.teardown();
  }

  // Row-hash substitution at the recorded tip counter → FATAL rollback.
  var fx2 = await _coordFixture();
  try {
    await _seed(fx2.driver,
      "CREATE TABLE _blamejs_audit_tip (scope TEXT, atMonotonicCounter INTEGER, rowHash TEXT)");
    await _seed(fx2.driver, "CREATE TABLE _blamejs_audit_log (monotonicCounter INTEGER, rowHash TEXT)");
    await _seed(fx2.driver,
      "INSERT INTO _blamejs_audit_tip (scope, atMonotonicCounter, rowHash) VALUES ('audit', 5, 'HASH_A')");
    await _seed(fx2.driver,
      "INSERT INTO _blamejs_audit_log (monotonicCounter, rowHash) VALUES (5, 'HASH_B')");
    var s2 = _makeStubProvider();
    var threw2 = null;
    try { await _initFollowerAgainst("ops", s2.provider); } catch (e) { threw2 = e; }
    check("row-hash substitution refuses boot", threw2 && threw2.code === "ROLLBACK_DETECTED");
    check("row-hash substitution message notes the mismatch",
          threw2 && /row-hash mismatch/.test(threw2.message));
  } finally {
    await fx2.teardown();
  }

  // A non-missing-table query error is re-thrown, not swallowed as a skip.
  var fx3 = await _coordFixture();
  try {
    // Tip table exists but lacks the queried columns → "no such column".
    await _seed(fx3.driver, "CREATE TABLE _blamejs_audit_tip (scope TEXT)");
    var s3 = _makeStubProvider();
    var threw3 = null;
    try { await _initFollowerAgainst("ops", s3.provider); } catch (e) { threw3 = e; }
    check("a non-missing-table error propagates out of the rollback check",
          threw3 && /no such column/i.test(threw3.message || ""));
  } finally {
    await fx3.teardown();
  }

  // Empty tip table → skip (first cluster boot / operator-cleared).
  var fx4 = await _coordFixture();
  try {
    await _seed(fx4.driver,
      "CREATE TABLE _blamejs_audit_tip (scope TEXT, atMonotonicCounter INTEGER, rowHash TEXT)");
    await _seed(fx4.driver,
      "CREATE TABLE _blamejs_consent_tip (scope TEXT, atMonotonicCounter INTEGER, rowHash TEXT)");
    var s4 = _makeStubProvider();
    var threw4 = null;
    try { await _initFollowerAgainst("ops", s4.provider); } catch (e) { threw4 = e; }
    check("an empty tip table skips the rollback check and boots", threw4 === null);
    check("empty-tip boot reaches cluster mode", b.cluster.isClusterMode() === true);
  } finally {
    await fx4.teardown();
  }

  // Consistent chains → the rollback check passes for both audit and
  // consent, exercising both the hash-absent and hash-present branches.
  var fx5 = await _coordFixture();
  try {
    // audit: tip rowHash NULL, counter present in the log → hash-absent OK.
    await _seed(fx5.driver,
      "CREATE TABLE _blamejs_audit_tip (scope TEXT, atMonotonicCounter INTEGER, rowHash TEXT)");
    await _seed(fx5.driver, "CREATE TABLE _blamejs_audit_log (monotonicCounter INTEGER, rowHash TEXT)");
    await _seed(fx5.driver,
      "INSERT INTO _blamejs_audit_tip (scope, atMonotonicCounter, rowHash) VALUES ('audit', 2, NULL)");
    await _seed(fx5.driver,
      "INSERT INTO _blamejs_audit_log (monotonicCounter, rowHash) VALUES (2, 'X')");
    // consent: tip rowHash present + matching log row → hash-present OK.
    await _seed(fx5.driver,
      "CREATE TABLE _blamejs_consent_tip (scope TEXT, atMonotonicCounter INTEGER, rowHash TEXT)");
    await _seed(fx5.driver, "CREATE TABLE _blamejs_consent_log (monotonicCounter INTEGER, rowHash TEXT)");
    await _seed(fx5.driver,
      "INSERT INTO _blamejs_consent_tip (scope, atMonotonicCounter, rowHash) VALUES ('consent', 3, 'HASH_C')");
    await _seed(fx5.driver,
      "INSERT INTO _blamejs_consent_log (monotonicCounter, rowHash) VALUES (3, 'HASH_C')");
    var s5 = _makeStubProvider();
    var threw5 = null;
    try { await _initFollowerAgainst("ops", s5.provider); } catch (e) { threw5 = e; }
    check("consistent chains pass the rollback check", threw5 === null);
    check("consistent-chain boot reaches cluster mode", b.cluster.isClusterMode() === true);
  } finally {
    await fx5.teardown();
  }
}

// ---- vault-key consistency ----

async function testVaultKeyConsistency() {
  // Cross-node drift with no rotation declared → FATAL refusal.
  var fx1 = await _coordFixture();
  try {
    await _seed(fx1.driver,
      "CREATE TABLE _blamejs_cluster_state (scope TEXT PRIMARY KEY, vaultKeyFp TEXT, " +
      "recordedAt INTEGER, recordedByNode TEXT)");
    await _seed(fx1.driver,
      "INSERT INTO _blamejs_cluster_state (scope, vaultKeyFp, recordedAt, recordedByNode) " +
      "VALUES ('state', ?, ?, 'peer-node')", [_bogusFp("b"), Date.now()]);
    var s = _makeStubProvider();
    var threw = null;
    try { await _initFollowerAgainst("ops", s.provider); } catch (e) { threw = e; }
    check("undeclared vault-key drift refuses boot", threw && threw.code === "VAULT_KEY_DRIFT");
  } finally {
    await fx1.teardown();
  }

  // Rotation declared but the local key doesn't match the blessed one.
  var fx2 = await _coordFixture();
  try {
    await _seed(fx2.driver,
      "CREATE TABLE _blamejs_cluster_state (scope TEXT PRIMARY KEY, vaultKeyFp TEXT, " +
      "recordedAt INTEGER, recordedByNode TEXT)");
    await _seed(fx2.driver,
      "INSERT INTO _blamejs_cluster_state (scope, vaultKeyFp, recordedAt, recordedByNode) " +
      "VALUES ('state', ?, ?, 'peer-node')", [_bogusFp("b"), Date.now()]);
    var s2 = _makeStubProvider();
    var threw2 = null;
    try {
      await b.cluster.init({
        nodeId: "rot-mismatch", role: "follower", provider: s2.provider,
        externalDbBackend: "ops", dialect: "sqlite",
        acceptVaultKeyRotation: true, expectedVaultKeyFp: _bogusFp("0"),
        leaseTtl: C.TIME.seconds(30), heartbeatInterval: C.TIME.seconds(15),
      });
    } catch (e) { threw2 = e; }
    check("a blessed fingerprint the local key can't match refuses boot",
          threw2 && threw2.code === "VAULT_KEY_ROTATION_MISMATCH");
  } finally {
    await fx2.teardown();
  }

  // Rotation adopted: the canonical row advances to the local fingerprint
  // and the rotation epoch bumps. The pre-seeded row already carries a
  // rotationEpoch column, exercising the swallowed "column exists" ALTER.
  var fx3 = await _coordFixture();
  try {
    await _seed(fx3.driver,
      "CREATE TABLE _blamejs_cluster_state (scope TEXT PRIMARY KEY, vaultKeyFp TEXT, " +
      "recordedAt INTEGER, recordedByNode TEXT, rotationEpoch INTEGER)");
    await _seed(fx3.driver,
      "INSERT INTO _blamejs_cluster_state (scope, vaultKeyFp, recordedAt, recordedByNode, rotationEpoch) " +
      "VALUES ('state', ?, ?, 'peer-node', 5)", [_bogusFp("c"), Date.now()]);
    var s3 = _makeStubProvider();
    var threw3 = null;
    try {
      await b.cluster.init({
        nodeId: "rot-adopt", role: "follower", provider: s3.provider,
        externalDbBackend: "ops", dialect: "sqlite",
        acceptVaultKeyRotation: true,
        leaseTtl: C.TIME.seconds(30), heartbeatInterval: C.TIME.seconds(15),
      });
    } catch (e) { threw3 = e; }
    check("a declared rotation is adopted and boots", threw3 === null);
    // The canonical row now holds a real fingerprint (not the bogus seed)
    // and the epoch advanced past the seeded value.
    var after = await _seed(fx3.driver,
      "SELECT vaultKeyFp, rotationEpoch FROM _blamejs_cluster_state WHERE scope = 'state'");
    var row = after.rows && after.rows[0];
    check("adoption replaces the canonical fingerprint",
          row && row.vaultKeyFp !== _bogusFp("c") && row.vaultKeyFp.length === 128);
    check("adoption bumps the rotation epoch", row && Number(row.rotationEpoch) === 6);
  } finally {
    await fx3.teardown();
  }
}

// ---- vault-key consistency: fail-closed guards via lying backends ----

// A backend that accepts the cluster-state INSERT but reports no row on the
// follow-up SELECT — modelling an external DB silently dropping the write.
function _makeStateVanishesDriver() {
  return {
    connect: async function () { return {}; },
    query: async function (_client, sqlText) {
      if (/audit_tip|consent_tip/i.test(sqlText)) throw new Error("no such table: tip");
      if (/^\s*INSERT\s+INTO\s+_blamejs_cluster_state/i.test(sqlText)) return { rows: [], rowCount: 1 };
      if (/^\s*ALTER\s+TABLE/i.test(sqlText)) return { rows: [], rowCount: 0 };
      if (/_blamejs_cluster_state/i.test(sqlText)) return { rows: [] };
      return { rows: [], rowCount: 0 };
    },
    close: async function () {},
  };
}

// A backend where the post-adoption re-read reports a fingerprint that is
// neither the old canonical nor this node's — a concurrent peer advancing
// the cluster to a third key the declared rotation does not cover.
function _makeConcurrentDriftDriver() {
  var selects = 0;
  return {
    connect: async function () { return {}; },
    query: async function (_client, sqlText) {
      if (/audit_tip|consent_tip/i.test(sqlText)) throw new Error("no such table: tip");
      if (/^\s*INSERT\s+INTO\s+_blamejs_cluster_state/i.test(sqlText)) return { rows: [], rowCount: 0 };
      if (/^\s*ALTER\s+TABLE/i.test(sqlText)) return { rows: [], rowCount: 0 };
      if (/^\s*UPDATE\s+_blamejs_cluster_state/i.test(sqlText)) return { rows: [], rowCount: 1 };
      if (/_blamejs_cluster_state/i.test(sqlText)) {
        selects += 1;
        // 1st select = canonical read; 2nd = post-adopt re-read. Both
        // report a foreign fingerprint (never this node's). The canonical
        // row carries a null rotationEpoch (a legacy pre-epoch row), so the
        // epoch defaults to 0 before the bump.
        var fp = selects === 1 ? _bogusFp("a") : _bogusFp("d");
        var epoch = selects === 1 ? null : 1;
        return { rows: [{ vaultKeyFp: fp, recordedByNode: "peer", recordedAt: 1, rotationEpoch: epoch }] };
      }
      return { rows: [], rowCount: 0 };
    },
    close: async function () {},
  };
}

// A backend where the tip tables are absent (skip) but the cluster-state
// upsert fails for a reason that is NOT a missing relation — the fault must
// propagate, not be mistaken for a gates-only skip.
function _makeStateUpsertErrorDriver() {
  return {
    connect: async function () { return {}; },
    query: async function (_client, sqlText) {
      if (/audit_tip|consent_tip/i.test(sqlText)) throw new Error("no such table: tip");
      if (/^\s*INSERT\s+INTO\s+_blamejs_cluster_state/i.test(sqlText)) {
        throw new Error("disk I/O error while writing cluster state");
      }
      return { rows: [], rowCount: 0 };
    },
    close: async function () {},
  };
}

// A backend surfacing structured missing-relation faults (MySQL errno 1146
// on the tip tables, Postgres SQLSTATE 42P01 on the state table) so the
// classifier's code/errno branch is exercised, not just its message regex.
function _makeStructuredMissingRelationDriver() {
  return {
    connect: async function () { return {}; },
    query: async function (_client, sqlText) {
      if (/audit_tip|consent_tip/i.test(sqlText)) {
        var e = new Error("Table 'db.tip' doesn't exist");
        e.errno = 1146; e.code = "ER_NO_SUCH_TABLE"; e.sqlState = "42S02";
        throw e;
      }
      var e2 = new Error("relation missing");
      e2.code = "42P01";
      throw e2;
    },
    close: async function () {},
  };
}

async function _runWithCustomBackend(backends, provider, initOpts) {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cluster-drv-"));
  b.cluster._resetForTest();
  await setupTestDb(tmpDir);
  b.externalDb.init({ backends: backends });
  var threw = null;
  try { await b.cluster.init(initOpts); } catch (e) { threw = e; }
  return {
    threw: threw,
    teardown: async function () {
      try { await b.cluster.shutdown(); } catch (_e) { /* idempotent */ }
      try { await b.externalDb.shutdown(); } catch (_e) { /* best-effort */ }
      await teardownTestDb(tmpDir);
    },
  };
}

async function testVaultKeyFailClosedGuards() {
  var baseOpts = {
    role: "follower", externalDbBackend: "x", dialect: "sqlite",
    leaseTtl: C.TIME.seconds(30), heartbeatInterval: C.TIME.seconds(15),
  };

  // External DB not honoring the state write → fail closed.
  var d1 = _makeStateVanishesDriver();
  var r1 = await _runWithCustomBackend(
    { x: { connect: d1.connect, query: d1.query, close: d1.close } },
    _makeStubProvider().provider,
    Object.assign({ nodeId: "state-vanish", provider: _makeStubProvider().provider }, baseOpts));
  try {
    check("a vanished cluster-state row refuses boot",
          r1.threw && r1.threw.code === "CLUSTER_STATE_MISSING");
  } finally { await r1.teardown(); }

  // Concurrent peer advanced to a third key after we adopted → fail closed.
  var d2 = _makeConcurrentDriftDriver();
  var r2 = await _runWithCustomBackend(
    { x: { connect: d2.connect, query: d2.query, close: d2.close } },
    _makeStubProvider().provider,
    Object.assign({ nodeId: "concurrent-drift", provider: _makeStubProvider().provider,
                    acceptVaultKeyRotation: true }, baseOpts));
  try {
    check("a concurrent divergent adoption refuses boot",
          r2.threw && r2.threw.code === "VAULT_KEY_DRIFT" &&
          /after rotation-accept/.test(r2.threw.message));
  } finally { await r2.teardown(); }

  // A non-missing-relation state-upsert fault propagates (not skipped).
  var dErr = _makeStateUpsertErrorDriver();
  var rErr = await _runWithCustomBackend(
    { x: { connect: dErr.connect, query: dErr.query, close: dErr.close } },
    _makeStubProvider().provider,
    Object.assign({ nodeId: "state-upsert-error", provider: _makeStubProvider().provider }, baseOpts));
  try {
    check("a non-missing-relation state-upsert fault propagates",
          rErr.threw && /disk I\/O error/.test(rErr.threw.message || ""));
  } finally { await rErr.teardown(); }

  // Structured missing-relation codes classify as skip (not re-thrown).
  var d3 = _makeStructuredMissingRelationDriver();
  var r3 = await _runWithCustomBackend(
    { x: { connect: d3.connect, query: d3.query, close: d3.close } },
    _makeStubProvider().provider,
    Object.assign({ nodeId: "structured-missing", provider: _makeStubProvider().provider }, baseOpts));
  try {
    check("structured missing-relation faults skip the checks and boot", r3.threw === null);
    check("structured-missing boot reaches cluster mode", b.cluster.isClusterMode() === true);
  } finally { await r3.teardown(); }
}

// ---- vault not initialized → gates-only skip ----

async function testVaultNotInitializedGatesOnly() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cluster-noVault-"));
  b.cluster._resetForTest();
  // Deliberately do NOT init the vault: a gates-only cluster (leader
  // election wired, framework sealed-column state still local) must skip
  // the vault-key consistency check rather than fail boot.
  b.vault._resetForTest();

  var dbPath = path.join(tmpDir, "ha-coord.db");
  var driver = _makeSqliteDriver(dbPath);
  b.externalDb.init({
    backends: { ops: { connect: driver.connect, query: driver.query, close: driver.close } },
  });
  var s = _makeStubProvider();
  try {
    var threw = null;
    try { await _initFollowerAgainst("ops", s.provider); } catch (e) { threw = e; }
    check("gates-only cluster boots without an initialized vault", threw === null);
    check("gates-only cluster reaches cluster mode", b.cluster.isClusterMode() === true);
  } finally {
    try { await b.cluster.shutdown(); } catch (_e) { /* idempotent */ }
    try { await b.externalDb.shutdown(); } catch (_e) { /* best-effort */ }
    try { driver._close(); } catch (_e) { /* best-effort */ }
    b.cluster._resetForTest();
    b.vault._resetForTest();
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) { /* best-effort */ }
  }
}

async function run() {
  await testExternalDbBackendAndOnTransition();
  await testInitConfigValidation();
  await testSyncSurfaceAndGetters();
  await testHeartbeatStateMachine();
  await testCurrentLeaderAndDiscovery();
  await testChainTipRollback();
  await testVaultKeyConsistency();
  await testVaultKeyFailClosedGuards();
  await testVaultNotInitializedGatesOnly();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("[cluster] OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e); process.exit(1); }
  );
}
