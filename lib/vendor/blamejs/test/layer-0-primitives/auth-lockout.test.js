"use strict";
/**
 * b.auth.lockout — per-key failed-attempt tracking with backoff lockouts.
 *
 * Run standalone: `node test/layer-0-primitives/auth-lockout.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b               = helpers.b;
var check           = helpers.check;
var setupTestDb     = helpers.setupTestDb;
var teardownTestDb  = helpers.teardownTestDb;
var fs              = helpers.fs;
var os              = helpers.os;
var path            = helpers.path;

var C = b.constants;

function _tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-lockout-")); }

function _newCache(namespace) {
  return b.cache.create({ namespace: namespace, backend: "memory" });
}

// Capture-shaped audit fixture matching b.audit.safeEmit contract
function _captureAudit() {
  var captured = [];
  return {
    safeEmit: function (event) { captured.push(event); },
    captured: captured,
    byAction: function (action) {
      return captured.filter(function (e) { return e.action === action; });
    },
  };
}

// Capture-shaped observability fixture matching b.observability.event
function _captureObs() {
  var captured = [];
  return {
    event: function (name, value, labels) { captured.push({ name: name, value: value, labels: labels }); },
    tap:   function (_n, _a, fn) { return fn(); },
    captured: captured,
    byName: function (n) {
      return captured.filter(function (e) { return e.name === n; });
    },
  };
}

// ---- Surface ----

function testSurface() {
  check("b.auth namespace present",            typeof b.auth === "object");
  check("b.auth.lockout namespace present",    typeof b.auth.lockout === "object");
  check("b.auth.lockout.create is a function", typeof b.auth.lockout.create === "function");
  check("LockoutError class",                  typeof b.auth.lockout.LockoutError === "function");
  check("DEFAULTS frozen",                     Object.isFrozen(b.auth.lockout.DEFAULTS));
  check("DEFAULTS.maxAttempts 5",              b.auth.lockout.DEFAULTS.maxAttempts === 5);
  check("DEFAULTS.windowMs 15min",             b.auth.lockout.DEFAULTS.windowMs === C.TIME.minutes(15));
  check("DEFAULTS.lockoutDurations frozen",    Object.isFrozen(b.auth.lockout.DEFAULTS.lockoutDurations));
  check("DEFAULTS.lockoutDurations[0] 1min",   b.auth.lockout.DEFAULTS.lockoutDurations[0] === C.TIME.minutes(1));
  check("DEFAULTS.auditFailures true",         b.auth.lockout.DEFAULTS.auditFailures === true);
  check("DEFAULTS.auditEngaged true",          b.auth.lockout.DEFAULTS.auditEngaged === true);
  check("DEFAULTS.auditUnlock true",           b.auth.lockout.DEFAULTS.auditUnlock === true);
  check("DEFAULTS.auditSuccess false",         b.auth.lockout.DEFAULTS.auditSuccess === false);
}

// ---- Input validation (rejects bad opts at create time) ----

function testCreateRejectsBadOpts() {
  var threw;

  threw = false;
  try { b.auth.lockout.create(); } catch (_e) { threw = true; }
  check("create() requires opts (cache + namespace)", threw);

  threw = false;
  try { b.auth.lockout.create({}); } catch (_e) { threw = true; }
  check("create() rejects missing cache",           threw);

  threw = false;
  try { b.auth.lockout.create({ cache: {} }); } catch (_e) { threw = true; }
  check("create() rejects malformed cache",         threw);

  threw = false;
  try { b.auth.lockout.create({ cache: _newCache("x") }); } catch (_e) { threw = true; }
  check("create() rejects missing namespace",       threw);

  threw = false;
  try {
    b.auth.lockout.create({
      cache: _newCache("x"), namespace: "login", maxAttempts: 0,
    });
  } catch (_e) { threw = true; }
  check("create() rejects maxAttempts < 1",         threw);

  threw = false;
  try {
    b.auth.lockout.create({
      cache: _newCache("x"), namespace: "login", maxAttempts: 1.5,
    });
  } catch (_e) { threw = true; }
  check("create() rejects non-integer maxAttempts", threw);

  threw = false;
  try {
    b.auth.lockout.create({
      cache: _newCache("x"), namespace: "login", windowMs: -1,
    });
  } catch (_e) { threw = true; }
  check("create() rejects negative windowMs",       threw);

  threw = false;
  try {
    b.auth.lockout.create({
      cache: _newCache("x"), namespace: "login", lockoutDurations: [],
    });
  } catch (_e) { threw = true; }
  check("create() rejects empty lockoutDurations array", threw);

  threw = false;
  try {
    b.auth.lockout.create({
      cache: _newCache("x"), namespace: "login", lockoutDurations: ["bad"],
    });
  } catch (_e) { threw = true; }
  check("create() rejects non-numeric lockoutDurations entry", threw);

  threw = false;
  try {
    b.auth.lockout.create({
      cache: _newCache("x"), namespace: "login", audit: { notSafeEmit: function () {} },
    });
  } catch (_e) { threw = true; }
  check("create() rejects audit without safeEmit fn", threw);

  threw = false;
  try {
    b.auth.lockout.create({
      cache: _newCache("x"), namespace: "login", clock: "Date.now",
    });
  } catch (_e) { threw = true; }
  check("create() rejects non-fn clock",            threw);

  threw = false;
  try {
    b.auth.lockout.create({
      cache: _newCache("x"), namespace: "login", BAD_OPT: 1,
    });
  } catch (_e) { threw = true; }
  check("create() rejects unknown opt",             threw);
}

async function testKeyValidation() {
  var lockout = b.auth.lockout.create({
    cache: _newCache("ns-key-val"), namespace: "login",
  });
  var threw;

  threw = false;
  try { await lockout.recordFailure(""); } catch (_e) { threw = true; }
  check("recordFailure rejects empty key",     threw);

  threw = false;
  try { await lockout.recordFailure(null); } catch (_e) { threw = true; }
  check("recordFailure rejects null key",      threw);

  threw = false;
  try { await lockout.recordSuccess(123); } catch (_e) { threw = true; }
  check("recordSuccess rejects non-string key", threw);

  threw = false;
  try { await lockout.check(undefined); } catch (_e) { threw = true; }
  check("check rejects undefined key",          threw);

  threw = false;
  try { await lockout.unlock(""); } catch (_e) { threw = true; }
  check("unlock rejects empty key",             threw);
}

// ---- Counter behavior ----

async function testRecordFailureCounter() {
  var lockout = b.auth.lockout.create({
    cache: _newCache("ns-counter"), namespace: "login", maxAttempts: 3,
  });

  var v1 = await lockout.recordFailure("alice");
  check("attempt 1: not locked",  v1.locked === false);
  check("attempt 1: attempts=1",  v1.attempts === 1);

  var v2 = await lockout.recordFailure("alice");
  check("attempt 2: not locked",  v2.locked === false);
  check("attempt 2: attempts=2",  v2.attempts === 2);

  var v3 = await lockout.recordFailure("alice");
  check("attempt 3 (= max): locked",     v3.locked === true);
  check("attempt 3: lockedUntil set",     typeof v3.lockedUntil === "number");
  check("attempt 3: attempts reset to 0", v3.attempts === 0);

  var alice = await lockout.check("alice");
  check("check: locked after threshold",   alice.locked === true);
  check("check: lockedUntil exposed",      typeof alice.lockedUntil === "number");

  // bob is independent
  var bob = await lockout.check("bob");
  check("check: bob is unaffected",        bob.locked === false && bob.attempts === 0);
}

// Concurrent failures on one key must each be counted. recordFailure reads
// the counter from the async cache, increments, and writes it back; without
// per-key serialization, N parallel calls all read the same pre-write value
// and the counter lands at 1 — an attacker who fires attempts in parallel
// stays under the lockout threshold forever.
async function testConcurrentFailuresAllCounted() {
  var lockout = b.auth.lockout.create({
    cache: _newCache("ns-race"), namespace: "login", maxAttempts: 10,
  });
  await Promise.all([
    lockout.recordFailure("eve"),
    lockout.recordFailure("eve"),
    lockout.recordFailure("eve"),
    lockout.recordFailure("eve"),
    lockout.recordFailure("eve"),
  ]);
  var state = await lockout.check("eve");
  check("5 concurrent failures all counted (no lost update)", state.attempts === 5);
}

async function testNonMutatingCheck() {
  var lockout = b.auth.lockout.create({
    cache: _newCache("ns-nonmutating"), namespace: "login", maxAttempts: 5,
  });
  await lockout.recordFailure("k");
  var before = await lockout.attempts("k");
  await lockout.check("k");
  await lockout.check("k");
  await lockout.check("k");
  var after = await lockout.attempts("k");
  check("check() does not increment counter", before === after && before === 1);
}

async function testRecordSuccessClears() {
  var lockout = b.auth.lockout.create({
    cache: _newCache("ns-clears"), namespace: "login", maxAttempts: 5,
  });
  await lockout.recordFailure("k");
  await lockout.recordFailure("k");
  check("attempts before success",  (await lockout.attempts("k")) === 2);
  await lockout.recordSuccess("k");
  check("attempts after success=0", (await lockout.attempts("k")) === 0);
  var s = await lockout.check("k");
  check("check after success=clean", s.locked === false && s.attempts === 0);
}

async function testExponentialLadder() {
  // Use a fake clock so we can advance past the lockout window deterministically.
  var nowMs = 1700000000000;
  var lockout = b.auth.lockout.create({
    cache: _newCache("ns-ladder"), namespace: "login", maxAttempts: 2,
    lockoutDurations: [100, 500, 2000],  // small for the test
    windowMs: 50,                         // tiny so decay is easy
    clock: function () { return nowMs; },
  });

  // First lockout at attempt 2 → 100ms
  await lockout.recordFailure("k");
  var v1 = await lockout.recordFailure("k");
  check("ladder: 1st lockout duration ~100ms",  v1.lockedUntil === nowMs + 100);

  // Skip past the lockout AND the window decay so the next failure
  // still increments lockNumber
  nowMs += 200;

  await lockout.recordFailure("k");
  var v2 = await lockout.recordFailure("k");
  check("ladder: 2nd lockout duration ~500ms",  v2.lockedUntil === nowMs + 500);

  nowMs += 1000;

  await lockout.recordFailure("k");
  var v3 = await lockout.recordFailure("k");
  check("ladder: 3rd lockout duration ~2000ms", v3.lockedUntil === nowMs + 2000);

  nowMs += 3000;

  await lockout.recordFailure("k");
  var v4 = await lockout.recordFailure("k");
  check("ladder: 4th lockout clamps to last",   v4.lockedUntil === nowMs + 2000);
}

async function testCustomDurationFn() {
  var nowMs = 1700000000000;
  var lockout = b.auth.lockout.create({
    cache: _newCache("ns-fn"), namespace: "login", maxAttempts: 1,
    lockoutDurations: function (n) { return n * 1000; },  // 1s, 2s, 3s, ...
    windowMs: 50,
    clock: function () { return nowMs; },
  });
  var v1 = await lockout.recordFailure("k");
  check("custom-fn: 1st lockout = 1s", v1.lockedUntil === nowMs + 1000);
  nowMs += 2000;
  var v2 = await lockout.recordFailure("k");
  check("custom-fn: 2nd lockout = 2s", v2.lockedUntil === nowMs + 2000);
}

async function testWindowDecay() {
  var nowMs = 1700000000000;
  var lockout = b.auth.lockout.create({
    cache: _newCache("ns-decay"), namespace: "login",
    maxAttempts: 5,
    windowMs: 100,
    clock: function () { return nowMs; },
  });
  await lockout.recordFailure("k");
  await lockout.recordFailure("k");
  check("before decay: attempts=2",       (await lockout.attempts("k")) === 2);
  nowMs += 200;  // past window
  var v = await lockout.recordFailure("k");
  check("after window: counter reset to 1", v.attempts === 1);
}

// ---- Admin unlock ----

async function testAdminUnlock() {
  var lockout = b.auth.lockout.create({
    cache: _newCache("ns-unlock"), namespace: "login", maxAttempts: 2,
  });
  await lockout.recordFailure("k");
  await lockout.recordFailure("k");
  var locked = await lockout.check("k");
  check("pre-unlock: locked",     locked.locked === true);

  var hadLock = await lockout.unlock("k");
  check("unlock returns true on lockout removed", hadLock === true);

  var after = await lockout.check("k");
  check("post-unlock: not locked", after.locked === false);
  check("post-unlock: attempts=0", after.attempts === 0);

  // Idempotent — second unlock returns false
  var hadLock2 = await lockout.unlock("k");
  check("unlock idempotent (2nd call false)", hadLock2 === false);
}

async function testUnlockClearsAttemptsBelowThreshold() {
  var lockout = b.auth.lockout.create({
    cache: _newCache("ns-unlock-low"), namespace: "login", maxAttempts: 5,
  });
  await lockout.recordFailure("k");
  await lockout.recordFailure("k");
  // 2 failures, not yet locked but counter is non-zero
  var hadLock = await lockout.unlock("k");
  check("unlock with attempts-but-no-lock returns true", hadLock === true);
  check("attempts cleared",                              (await lockout.attempts("k")) === 0);
}

// ---- Audit emission ----

async function testAuditEmission() {
  var auditCap = _captureAudit();
  var lockout = b.auth.lockout.create({
    cache: _newCache("ns-audit"), namespace: "login", maxAttempts: 2,
    audit: auditCap,
  });
  await lockout.recordFailure("alice");
  await lockout.recordFailure("alice");

  var failures = auditCap.byAction("auth.lockout.failure");
  check("audit: 2 failure events emitted", failures.length === 2);

  var engaged = auditCap.byAction("auth.lockout.engaged");
  check("audit: 1 engaged event emitted",  engaged.length === 1);
  check("audit: engaged outcome=denied",   engaged[0].outcome === "denied");
  check("audit: engaged metadata.lockNumber=1",  engaged[0].metadata.lockNumber === 1);
  check("audit: engaged metadata.lockedUntil set",
                                            typeof engaged[0].metadata.lockedUntil === "number");

  await lockout.unlock("alice", { reason: "support ticket #42" });
  var unlocks = auditCap.byAction("auth.lockout.unlock");
  check("audit: unlock event emitted",     unlocks.length === 1);
  check("audit: unlock metadata.reason",   unlocks[0].metadata.reason === "support ticket #42");
  check("audit: unlock hadLock=true",      unlocks[0].metadata.hadLock === true);
}

async function testAuditSuccessOptIn() {
  var auditCap = _captureAudit();
  var lockout = b.auth.lockout.create({
    cache: _newCache("ns-audit-success"), namespace: "login",
    audit: auditCap, auditSuccess: true,
  });
  await lockout.recordFailure("alice");
  await lockout.recordSuccess("alice");
  var success = auditCap.byAction("auth.lockout.success");
  check("audit: success event emitted with auditSuccess:true", success.length === 1);
  check("audit: success metadata.attemptsCleared=1",
                                                    success[0].metadata.attemptsCleared === 1);
}

async function testAuditOptOut() {
  var auditCap = _captureAudit();
  var lockout = b.auth.lockout.create({
    cache: _newCache("ns-audit-out"), namespace: "login", maxAttempts: 2,
    audit: auditCap,
    auditFailures: false, auditEngaged: false, auditUnlock: false,
  });
  await lockout.recordFailure("alice");
  await lockout.recordFailure("alice");
  await lockout.unlock("alice");
  check("audit: 0 events when all flags off",     auditCap.captured.length === 0);
}

async function testFiveWsAuditPropagation() {
  var auditCap = _captureAudit();
  var lockout = b.auth.lockout.create({
    cache: _newCache("ns-5ws"), namespace: "login", maxAttempts: 2,
    audit: auditCap,
  });
  var fakeReq = {
    method:  "POST",
    url:     "/login",
    headers: { "user-agent": "Mozilla/5.0", "x-request-id": "req-abc" },
    socket:  { remoteAddress: "10.0.0.5" },
  };
  await lockout.recordFailure("alice", { req: fakeReq, reason: "bad-password" });
  var failure = auditCap.byAction("auth.lockout.failure")[0];
  check("5ws: actor.ip captured",          failure.actor.ip === "10.0.0.5");
  check("5ws: actor.userAgent captured",   failure.actor.userAgent === "Mozilla/5.0");
  check("5ws: actor.requestId captured",   failure.actor.requestId === "req-abc");
  check("5ws: actor.method captured",      failure.actor.method === "POST");
  check("5ws: metadata.reason captured",   failure.metadata.reason === "bad-password");
}

// ---- Observability emission ----

async function testObservabilityEmission() {
  var obsCap = _captureObs();
  var lockout = b.auth.lockout.create({
    cache: _newCache("ns-obs"), namespace: "login", maxAttempts: 2,
    observability: obsCap,
  });
  await lockout.recordFailure("k");
  await lockout.recordFailure("k");
  await lockout.recordSuccess("k");

  check("obs: failure event >= 2",
        obsCap.byName("auth.lockout.failure").length >= 2);
  check("obs: engaged event >= 1",
        obsCap.byName("auth.lockout.engaged").length >= 1);
  check("obs: success event >= 1",
        obsCap.byName("auth.lockout.success").length >= 1);

  var engaged = obsCap.byName("auth.lockout.engaged")[0];
  check("obs: engaged label.lockNumber present",
        engaged.labels && engaged.labels.lockNumber === "1");
}

// ---- Failure-during-lock ----

async function testFailureDuringLock() {
  var auditCap = _captureAudit();
  var lockout = b.auth.lockout.create({
    cache: _newCache("ns-during-lock"), namespace: "login", maxAttempts: 2,
    audit: auditCap,
  });
  await lockout.recordFailure("k");
  await lockout.recordFailure("k");  // engages lock
  // Caller skipped check() and called recordFailure on a locked account
  var v = await lockout.recordFailure("k");
  check("failure-during-lock: still locked",       v.locked === true);
  check("failure-during-lock: attempts unchanged", v.attempts === 0);

  var failures = auditCap.byAction("auth.lockout.failure");
  // 1 from each pre-lock + 1 during-lock = 3
  check("audit: failure during lock recorded",     failures.length === 3);
  var lastFailure = failures[failures.length - 1];
  check("audit: duringLock=true on locked failure", lastFailure.metadata.duringLock === true);
}

// ---- Backend-error fail-open ----

async function testBackendErrorFailOpen() {
  var obsCap = _captureObs();
  var brokenCache = {
    get: function () { return Promise.reject(new Error("backend down")); },
    set: function () { return Promise.reject(new Error("backend down")); },
    del: function () { return Promise.reject(new Error("backend down")); },
  };
  var lockout = b.auth.lockout.create({
    cache: brokenCache, namespace: "login", observability: obsCap,
  });
  // Should not throw; should fail-open
  var v = await lockout.recordFailure("k");
  check("fail-open: returns verdict on backend error", typeof v === "object");

  var s = await lockout.check("k");
  check("fail-open: check returns clean state on get-error",
                                                  s.locked === false && s.attempts === 0);

  var cacheErrors = obsCap.byName("auth.lockout.cache_error");
  check("fail-open: cache_error observability emitted", cacheErrors.length >= 1);
}

// ---- Cluster backend round-trip ----

async function testClusterBackend(tmpDir) {
  await setupTestDb(tmpDir);
  try {
    var clusterCache = b.cache.create({
      namespace: "auth.lockout.cluster",
      backend:   "cluster",
    });
    var lockout = b.auth.lockout.create({
      cache: clusterCache, namespace: "login", maxAttempts: 2,
    });
    await lockout.recordFailure("alice");
    var v = await lockout.recordFailure("alice");
    check("cluster: lockout engages",  v.locked === true);

    // Different lockout instance pointing at the same cache namespace
    // sees the same state — that's the cluster-shared property.
    var lockout2 = b.auth.lockout.create({
      cache: clusterCache, namespace: "login", maxAttempts: 2,
    });
    var s = await lockout2.check("alice");
    check("cluster: state shared across instances", s.locked === true);

    await lockout2.unlock("alice");
    var s2 = await lockout.check("alice");
    check("cluster: unlock from one instance clears the other", s2.locked === false);

    await clusterCache.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- Run ----

async function run() {
  var tmpDir = _tmp();
  try {
    testSurface();
    testCreateRejectsBadOpts();
    await testKeyValidation();
    await testRecordFailureCounter();
    await testConcurrentFailuresAllCounted();
    await testNonMutatingCheck();
    await testRecordSuccessClears();
    await testExponentialLadder();
    await testCustomDurationFn();
    await testWindowDecay();
    await testAdminUnlock();
    await testUnlockClearsAttemptsBelowThreshold();
    await testAuditEmission();
    await testAuditSuccessOptIn();
    await testAuditOptOut();
    await testFiveWsAuditPropagation();
    await testObservabilityEmission();
    await testFailureDuringLock();
    await testBackendErrorFailOpen();
    await testClusterBackend(tmpDir);
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_e) {}
  }
}

async function _testAtoKillSwitch() {
  var threw;
  try { await b.auth.atoKillSwitch.trigger({}); } catch (e) { threw = e; }
  check("atoKillSwitch.trigger requires userId",
    threw && /userId/.test(threw.message));

  try { await b.auth.atoKillSwitch.trigger({ userId: "u_42" }); } catch (e) { threw = e; }
  check("atoKillSwitch.trigger requires reason",
    threw && /reason/.test(threw.message));

  // Real ATO: needs a session backend wired. Without one, the call would
  // throw on the destroyAllForUser step. We verify only the validation
  // path here; the integration test exercises the full flow.
  check("atoKillSwitch error class registered",
    typeof b.auth.atoKillSwitch.AtoKillSwitchError === "function");
}

module.exports = { run: async function () { await run(); await _testAtoKillSwitch(); } };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
