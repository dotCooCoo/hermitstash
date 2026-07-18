// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.cache — caching primitive.
 *
 * Run standalone: `node test/layer-0-primitives/cache.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b              = helpers.b;
var fs             = helpers.fs;
var os             = helpers.os;
var path           = helpers.path;
var check          = helpers.check;
var setupTestDb    = helpers.setupTestDb;
var teardownTestDb = helpers.teardownTestDb;
var waitUntil      = helpers.waitUntil;

// ---- Surface ----

function testSurface() {
  check("b.cache namespace present",        typeof b.cache === "object");
  check("b.cache.create is a function",     typeof b.cache.create === "function");
  check("b.cache.CacheError class",         typeof b.cache.CacheError === "function");
  check("b.cache.DEFAULTS frozen",          Object.isFrozen(b.cache.DEFAULTS));
  check("DEFAULTS.backend memory",          b.cache.DEFAULTS.backend === "memory");
  check("DEFAULTS.maxEntries 10000",        b.cache.DEFAULTS.maxEntries === 10000);
  check("DEFAULTS.staleWhileRevalidate false (opt-in)",
        b.cache.DEFAULTS.staleWhileRevalidate === false);
  check("DEFAULTS.auditFailures true (signal default ON)",
        b.cache.DEFAULTS.auditFailures === true);
  check("DEFAULTS.auditClear true (operator action default ON)",
        b.cache.DEFAULTS.auditClear === true);
  check("DEFAULTS.ttlMs is finite positive",
        typeof b.cache.DEFAULTS.ttlMs === "number" && b.cache.DEFAULTS.ttlMs > 0);
  check("DEFAULTS.sweepIntervalMs is finite positive",
        typeof b.cache.DEFAULTS.sweepIntervalMs === "number" && b.cache.DEFAULTS.sweepIntervalMs >= 1000);

  var c = b.cache.create({ namespace: "surface" });
  check("instance.get fn",                  typeof c.get === "function");
  check("instance.set fn",                  typeof c.set === "function");
  check("instance.del fn",                  typeof c.del === "function");
  check("instance.has fn",                  typeof c.has === "function");
  check("instance.clear fn",                typeof c.clear === "function");
  check("instance.size fn",                 typeof c.size === "function");
  check("instance.wrap fn",                 typeof c.wrap === "function");
  check("instance.close fn",                typeof c.close === "function");
  check("instance.namespace echoed",        c.namespace === "surface");
  return c.close();
}

// ---- Input validation (rejects bad opts at create time) ----

async function testValidation() {
  var threwNoOpts = false;
  try { b.cache.create(); } catch (_e) { threwNoOpts = true; }
  check("create() with no opts throws",     threwNoOpts);

  var threwNoNs = false;
  try { b.cache.create({}); } catch (_e) { threwNoNs = true; }
  check("create() without namespace throws", threwNoNs);

  var threwBadNs = false;
  try { b.cache.create({ namespace: "" }); } catch (_e) { threwBadNs = true; }
  check("create() with empty namespace throws", threwBadNs);

  var threwColonNs = false;
  try { b.cache.create({ namespace: "has:colon" }); } catch (_e) { threwColonNs = true; }
  check("create() rejects ':' in namespace (cluster-key separator)",
        threwColonNs);

  var threwBadBackend = false;
  try { b.cache.create({ namespace: "n", backend: "redis" }); } catch (_e) { threwBadBackend = true; }
  check("create() with unknown backend string throws", threwBadBackend);

  var threwIncompleteBackend = false;
  try { b.cache.create({ namespace: "n", backend: { get: function () {} } }); }
  catch (_e) { threwIncompleteBackend = true; }
  check("create() with incomplete custom backend throws", threwIncompleteBackend);

  var threwNanTtl = false;
  try { b.cache.create({ namespace: "n", ttlMs: NaN }); } catch (_e) { threwNanTtl = true; }
  check("create() with NaN ttlMs throws",   threwNanTtl);

  var threwNegTtl = false;
  try { b.cache.create({ namespace: "n", ttlMs: -1 }); } catch (_e) { threwNegTtl = true; }
  check("create() with negative ttlMs throws", threwNegTtl);

  var infTtl = false;
  try {
    var ic = b.cache.create({ namespace: "n", ttlMs: Infinity });
    infTtl = true;
    await ic.close();
  } catch (_e) {}
  check("create() with Infinity ttlMs accepted",  infTtl);

  var threwMaxEntries = false;
  try { b.cache.create({ namespace: "n", maxEntries: 0 }); } catch (_e) { threwMaxEntries = true; }
  check("create() with zero maxEntries throws", threwMaxEntries);

  var threwSweep = false;
  try { b.cache.create({ namespace: "n", sweepIntervalMs: 100 }); } catch (_e) { threwSweep = true; }
  check("create() with sub-1000ms sweep throws", threwSweep);

  var threwBadAudit = false;
  try { b.cache.create({ namespace: "n", audit: { /* no safeEmit */ } }); } catch (_e) { threwBadAudit = true; }
  check("create() with non-conforming audit throws", threwBadAudit);

  var threwBadClock = false;
  try { b.cache.create({ namespace: "n", clock: 42 }); } catch (_e) { threwBadClock = true; }
  check("create() with non-fn clock throws", threwBadClock);

  // Key validation
  var c = b.cache.create({ namespace: "n" });
  var threwBadKey = false;
  try { await c.get(123); } catch (_e) { threwBadKey = true; }
  check("get(non-string) throws",            threwBadKey);

  var threwEmptyKey = false;
  try { await c.set("", "v"); } catch (_e) { threwEmptyKey = true; }
  check("set('') throws",                    threwEmptyKey);

  var threwWrapNoFn = false;
  try { await c.wrap("k", "not-a-fn"); } catch (_e) { threwWrapNoFn = true; }
  check("wrap(k, non-fn) throws",            threwWrapNoFn);

  var threwBadCallTtl = false;
  try { await c.set("k", "v", { ttlMs: NaN }); } catch (_e) { threwBadCallTtl = true; }
  check("set(k, v, { ttlMs: NaN }) throws",  threwBadCallTtl);

  await c.close();
}

// ---- Memory backend basics ----

async function testGetSetDel() {
  var c = b.cache.create({ namespace: "basic" });
  await c.set("a", 1);
  await c.set("b", { x: 2 });
  check("get('a') returns 1",               (await c.get("a")) === 1);
  check("get('b') returns object",          (await c.get("b")).x === 2);
  check("get('missing') returns undefined", (await c.get("missing")) === undefined);
  check("size() after 2 sets is 2",         (await c.size()) === 2);
  check("del('a') returns true",            (await c.del("a")) === true);
  check("del('a') second time returns false", (await c.del("a")) === false);
  check("size() after del is 1",            (await c.size()) === 1);
  check("has('b') true",                    (await c.has("b")) === true);
  check("has('a') false",                   (await c.has("a")) === false);
  await c.close();
}

// ---- TTL expiration ----

async function testTtlExpiration() {
  var clk = b.testing.fakeClock(1_000_000);
  var c = b.cache.create({
    namespace: "ttl",
    ttlMs:     100,
    clock:     clk.now,
  });
  await c.set("k", "v");
  check("fresh entry — get returns",         (await c.get("k")) === "v");
  clk.advance(50);
  check("within ttl — still cached",         (await c.get("k")) === "v");
  clk.advance(60);     // total 110ms — past ttl
  check("past ttl — get returns undefined",  (await c.get("k")) === undefined);
  check("past ttl — size now 0 (lazy purge)", (await c.size()) === 0);
  await c.close();
}

async function testPerCallTtlOverride() {
  var clk = b.testing.fakeClock(1_000_000);
  var c = b.cache.create({
    namespace: "ttl-override",
    ttlMs:     b.constants.TIME.minutes(5),
    clock:     clk.now,
  });
  await c.set("short", "v", { ttlMs: 10 });
  clk.advance(20);
  check("per-call ttlMs overrides instance default",
        (await c.get("short")) === undefined);

  await c.set("long", "v");   // uses instance default 5min
  clk.advance(b.constants.TIME.minutes(1));
  check("instance default still applies to other keys",
        (await c.get("long")) === "v");
  await c.close();
}

async function testInfinityTtl() {
  var clk = b.testing.fakeClock(1_000_000);
  var c = b.cache.create({
    namespace: "infinity",
    ttlMs:     1,
    clock:     clk.now,
  });
  await c.set("k", "v", { ttlMs: Infinity });
  clk.advance(b.constants.TIME.days(365));
  check("Infinity ttl — entry survives massive clock advance",
        (await c.get("k")) === "v");
  await c.close();
}

async function testZeroTtl() {
  var c = b.cache.create({ namespace: "zero" });
  await c.set("k", "v", { ttlMs: 0 });
  check("ttlMs=0 means do-not-cache — get returns undefined",
        (await c.get("k")) === undefined);
  check("ttlMs=0 — size remains 0", (await c.size()) === 0);
  await c.close();
}

// ---- LRU ----

async function testLruEvictionOnSize() {
  var c = b.cache.create({ namespace: "lru", maxEntries: 3 });
  await c.set("a", 1);
  await c.set("b", 2);
  await c.set("c", 3);
  await c.set("d", 4);    // evicts oldest (a)
  check("LRU evicts oldest on overflow",
        (await c.get("a")) === undefined &&
        (await c.get("d")) === 4);
  check("LRU keeps recent entries",
        (await c.get("b")) === 2 &&
        (await c.get("c")) === 3);
  await c.close();
}

async function testLruRecencyBumpOnGet() {
  var c = b.cache.create({ namespace: "lru-recency", maxEntries: 3 });
  await c.set("a", 1);
  await c.set("b", 2);
  await c.set("c", 3);
  // Access 'a' to bump its recency above b/c
  await c.get("a");
  await c.set("d", 4);    // should evict 'b' (oldest now)
  check("get() bumps LRU recency — a survives, b evicted",
        (await c.get("a")) === 1 &&
        (await c.get("b")) === undefined);
  await c.close();
}

async function testHasDoesNotBumpRecency() {
  var c = b.cache.create({ namespace: "lru-has", maxEntries: 3 });
  await c.set("a", 1);
  await c.set("b", 2);
  await c.set("c", 3);
  // has() must NOT bump 'a' to most-recent
  await c.has("a");
  await c.set("d", 4);    // should still evict 'a' (oldest)
  check("has() does NOT bump LRU recency — a still evicted first",
        (await c.get("a")) === undefined);
  await c.close();
}

// ---- Sweep timer ----

async function testSweepTimer() {
  var clk = b.testing.fakeClock(1_000_000);
  var c = b.cache.create({
    namespace:        "sweep",
    ttlMs:            10,
    sweepIntervalMs:  1000,
    clock:            clk.now,
  });
  await c.set("a", 1);
  await c.set("b", 2);
  clk.advance(100);
  // Manually trigger sweep without waiting for interval — invoke the
  // backend's sweep cycle by calling size() (which doesn't sweep) and
  // checking that size reflects 0 live (lazy purge).
  check("sweep + lazy purge — size reflects expired",
        (await c.size()) === 0);
  await c.close();
}

// ---- clear() ----

async function testClear() {
  var c = b.cache.create({ namespace: "clear" });
  await c.set("a", 1);
  await c.set("b", 2);
  await c.set("c", 3);
  var purged = await c.clear();
  check("clear() returns purged count",     purged === 3);
  check("size() after clear is 0",          (await c.size()) === 0);
  check("get() after clear returns undefined", (await c.get("a")) === undefined);
  await c.close();
}

// ---- wrap() ----

async function testWrapBasic() {
  var c = b.cache.create({ namespace: "wrap" });
  var calls = 0;
  var fn = function () { calls++; return Promise.resolve("computed"); };
  var v1 = await c.wrap("k", fn);
  var v2 = await c.wrap("k", fn);
  check("wrap returns computed value",       v1 === "computed" && v2 === "computed");
  check("wrap calls fn exactly once",        calls === 1);
  await c.close();
}

async function testWrapSingleFlight() {
  var c = b.cache.create({ namespace: "wrap-sf" });
  var calls = 0;
  var fn = function () {
    calls++;
    return new Promise(function (r) { setImmediate(function () { r("computed"); }); });
  };
  var [v1, v2, v3] = await Promise.all([
    c.wrap("k", fn),
    c.wrap("k", fn),
    c.wrap("k", fn),
  ]);
  check("single-flight: all callers get same value",
        v1 === "computed" && v2 === "computed" && v3 === "computed");
  check("single-flight: fn invoked once",    calls === 1);
  await c.close();
}

async function testWrapSingleFlightOptOut() {
  var c = b.cache.create({ namespace: "wrap-fanout" });
  var calls = 0;
  var fn = function () {
    calls++;
    return new Promise(function (r) { setImmediate(function () { r("computed"); }); });
  };
  await Promise.all([
    c.wrap("k", fn, { singleFlight: false }),
    c.wrap("k", fn, { singleFlight: false }),
  ]);
  check("singleFlight=false → fn invoked twice (concurrent)",
        calls === 2);
  await c.close();
}

async function testWrapPerCallTtl() {
  var clk = b.testing.fakeClock(1_000_000);
  var c = b.cache.create({
    namespace: "wrap-ttl",
    ttlMs:     b.constants.TIME.minutes(5),
    clock:     clk.now,
  });
  var calls = 0;
  var fn = function () { calls++; return "v"; };
  await c.wrap("k", fn, { ttlMs: 10 });
  clk.advance(20);
  await c.wrap("k", fn, { ttlMs: 10 });    // expired, recomputes
  check("wrap respects per-call ttlMs override (recomputed after short ttl)",
        calls === 2);
  await c.close();
}

// ---- Stale-while-revalidate ----

async function testStaleWhileRevalidate() {
  var clk = b.testing.fakeClock(1_000_000);
  var c = b.cache.create({
    namespace:            "swr",
    ttlMs:                100,
    staleWhileRevalidate: true,
    clock:                clk.now,
  });
  var version = 1;
  var fn = function () { return Promise.resolve("v" + version); };
  var first = await c.wrap("k", fn);
  check("SWR: first call returns fresh",     first === "v1");

  // Past soft TTL, before hard TTL: returns stale + triggers refresh
  clk.advance(150);     // 150 > 100ms soft, < 200ms hard
  version = 2;
  var stale = await c.wrap("k", fn);
  check("SWR: past-soft returns stale value", stale === "v1");

  // Background refresh has been kicked off; wait for microtasks
  await new Promise(function (r) { setImmediate(r); });
  await new Promise(function (r) { setImmediate(r); });

  clk.advance(1);       // small advance so backend doesn't think it's stale again
  var fresh = await c.wrap("k", fn);
  check("SWR: subsequent call returns refreshed value",
        fresh === "v2");
  await c.close();
}

// ---- Audit emission ----

async function testAuditClearedOn() {
  var audit = b.testing.captureAudit();
  var c = b.cache.create({
    namespace: "audit-clear",
    audit:     audit,
  });
  await c.set("k", "v");
  await c.clear();
  check("default: cache.cleared audited when audit wired",
        audit.byAction("cache.cleared").length === 1);
  await c.close();
}

async function testAuditClearedOptOut() {
  var audit = b.testing.captureAudit();
  var c = b.cache.create({
    namespace:  "audit-clear-off",
    audit:      audit,
    auditClear: false,
  });
  await c.set("k", "v");
  await c.clear();
  check("opt-out: cache.cleared NOT emitted when auditClear=false",
        audit.byAction("cache.cleared").length === 0);
  await c.close();
}

async function testAuditCarriesActorContext() {
  var audit = b.testing.captureAudit();
  var c = b.cache.create({
    namespace: "audit-actor",
    audit:     audit,
  });
  var fakeReq = b.testing.mockReq({
    ip:        "10.0.0.5",
    userAgent: "tester/1.0",
    requestId: "req-42",
    method:    "POST",
    url:       "/admin/cache/clear",
  });
  await c.set("k", "v");
  await c.clear({ req: fakeReq });
  var clearedEvent = audit.byAction("cache.cleared")[0];
  check("audit carries WHO/WHERE/HOW from req via extractActorContext",
        !!clearedEvent &&
        clearedEvent.actor.ip === "10.0.0.5" &&
        clearedEvent.actor.userAgent === "tester/1.0" &&
        clearedEvent.actor.requestId === "req-42" &&
        clearedEvent.actor.method === "POST" &&
        clearedEvent.actor.route === "/admin/cache/clear");
  await c.close();
}

async function testAuditBackendFailed() {
  var audit = b.testing.captureAudit();
  var failingBackend = {
    get:   function () { return Promise.reject(new Error("backend dead")); },
    set:   function () { return Promise.reject(new Error("backend dead")); },
    del:   function () { return Promise.reject(new Error("backend dead")); },
    clear: function () { return Promise.reject(new Error("backend dead")); },
    size:  function () { return Promise.reject(new Error("backend dead")); },
    close: function () { return Promise.resolve(); },
  };
  var c = b.cache.create({
    namespace: "audit-fail",
    backend:   failingBackend,
    audit:     audit,
  });
  var threw = false;
  try { await c.set("k", "v"); } catch (_e) { threw = true; }
  check("backend error propagates to caller", threw);
  check("backend failure emits cache.backend.failed audit",
        audit.byAction("cache.backend.failed").length === 1);
  await c.close();
}

async function testAuditFailuresOptOut() {
  var audit = b.testing.captureAudit();
  var failingBackend = {
    get:   function () { return Promise.reject(new Error("dead")); },
    set:   function () { return Promise.reject(new Error("dead")); },
    del:   function () { return Promise.reject(new Error("dead")); },
    clear: function () { return Promise.reject(new Error("dead")); },
    size:  function () { return Promise.reject(new Error("dead")); },
    close: function () { return Promise.resolve(); },
  };
  var c = b.cache.create({
    namespace:     "audit-fail-off",
    backend:       failingBackend,
    audit:         audit,
    auditFailures: false,
  });
  try { await c.set("k", "v"); } catch (_e) {}
  check("opt-out: cache.backend.failed NOT emitted when auditFailures=false",
        audit.byAction("cache.backend.failed").length === 0);
  await c.close();
}

// ---- Custom backend ----

async function testCustomBackend() {
  var store = new Map();
  var closed = false;
  var custom = {
    get:   function (k) { return Promise.resolve(store.get(k)); },
    set:   function (k, v) { store.set(k, v); return Promise.resolve(); },
    del:   function (k) { var ex = store.has(k); store.delete(k); return Promise.resolve(ex); },
    has:   function (k) { return Promise.resolve(store.has(k)); },
    clear: function () { var n = store.size; store.clear(); return Promise.resolve(n); },
    size:  function () { return Promise.resolve(store.size); },
    close: function () { closed = true; return Promise.resolve(); },
  };
  var c = b.cache.create({ namespace: "custom", backend: custom });
  await c.set("k", "v");
  check("custom backend round-trip",        (await c.get("k")) === "v");
  check("custom backend size reflects state", (await c.size()) === 1);
  await c.close();
  check("custom backend close() invoked",   closed === true);
}

// ---- Closed-state ----

async function testClosedState() {
  var c = b.cache.create({ namespace: "closed" });
  await c.set("k", "v");
  await c.close();
  var threw = false;
  try { await c.get("k"); } catch (_e) { threw = true; }
  check("get after close throws BAD_STATE", threw);
  // Idempotent close
  await c.close();
  check("close() idempotent",               true);
}

// ---- Observability ----

async function testObservabilityEmission() {
  var cap = b.testing.captureMetricsTap();
  try {
    var c = b.cache.create({ namespace: "obs" });
    await c.set("k", "v");
    await c.get("k");          // hit
    await c.get("missing");    // miss
    await c.del("k");
    await c.close();
  } finally {
    cap.restore();
  }
  check("emits cache.set",                  cap.byName("cache.set").length > 0);
  check("emits cache.hit",                  cap.byName("cache.hit").length > 0);
  check("emits cache.miss",                 cap.byName("cache.miss").length > 0);
  check("emits cache.del",                  cap.byName("cache.del").length > 0);
}

async function testObservabilityWrapCompute() {
  var cap = b.testing.captureMetricsTap();
  try {
    var c = b.cache.create({ namespace: "obs-wrap" });
    await c.wrap("k", function () { return Promise.resolve("v"); });
    // Concurrent collapse
    await Promise.all([
      c.wrap("k2", function () { return new Promise(function (r) { setImmediate(function () { r("v"); }); }); }),
      c.wrap("k2", function () { return new Promise(function (r) { setImmediate(function () { r("v"); }); }); }),
    ]);
    await c.close();
  } finally {
    cap.restore();
  }
  check("wrap emits cache.wrap.compute",
        cap.byName("cache.wrap.compute").length > 0);
  check("wrap emits cache.wrap.singleflight.collapsed on concurrent calls",
        cap.byName("cache.wrap.singleflight.collapsed").length > 0);
}

// ---- Cluster backend ----

async function testClusterBackendBasics() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cache-"));
  try {
    await setupTestDb(tmpDir);
    var c = b.cache.create({
      namespace: "cb-basic",
      backend:   "cluster",
      ttlMs:     b.constants.TIME.minutes(5),
    });
    await c.set("a", { x: 1 });
    await c.set("b", "string");
    check("cluster get round-trip object",   (await c.get("a")).x === 1);
    check("cluster get round-trip string",   (await c.get("b")) === "string");
    check("cluster size",                    (await c.size()) === 2);
    check("cluster del",                     (await c.del("a")) === true);
    check("cluster size after del",          (await c.size()) === 1);
    check("cluster has",                     (await c.has("b")) === true);
    check("cluster has missing",             (await c.has("missing")) === false);
    var purged = await c.clear();
    check("cluster clear returns count",     purged === 1);
    check("cluster size after clear",        (await c.size()) === 0);
    await c.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClusterNamespaceIsolation() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cache-"));
  try {
    await setupTestDb(tmpDir);
    var c1 = b.cache.create({ namespace: "ns1", backend: "cluster" });
    var c2 = b.cache.create({ namespace: "ns2", backend: "cluster" });
    await c1.set("k", "v1");
    await c2.set("k", "v2");
    check("ns1 sees only its own value",     (await c1.get("k")) === "v1");
    check("ns2 sees only its own value",     (await c2.get("k")) === "v2");
    check("clearing ns1 doesn't affect ns2",
          (await c1.clear()) === 1 &&
          (await c2.get("k")) === "v2");
    await c1.close();
    await c2.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClusterTtlExpiration() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cache-"));
  try {
    await setupTestDb(tmpDir);
    var clk = b.testing.fakeClock(1_000_000);
    var c = b.cache.create({
      namespace: "cb-ttl",
      backend:   "cluster",
      ttlMs:     100,
      clock:     clk.now,
    });
    await c.set("k", "v");
    check("cluster fresh entry returns",     (await c.get("k")) === "v");
    clk.advance(200);
    check("cluster expired entry returns undefined",
          (await c.get("k")) === undefined);
    await c.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

// ---- run ----

// ---- v0.4.11 maxBytes + sliding TTL + tags ----

function _newCache(extra) {
  return b.cache.create(Object.assign({ namespace: "v411", backend: "memory" }, extra || {}));
}

async function testUpdateMemory() {
  var c = _newCache({ namespace: "upd-mem" });
  var r1 = await c.update("n", function (cur) { return { value: (cur || 0) + 1 }; });
  await c.update("n", function (cur) { return { value: cur + 1 }; });
  check("update memory: increments atomically", (await c.get("n")) === 2 && r1.value === 1);
  var ab = await c.update("n", function () { return { abort: { why: "nope" } }; });
  check("update memory: abort leaves value + returns aborted",
        ab.aborted && ab.aborted.why === "nope" && (await c.get("n")) === 2);
  var dl = await c.update("n", function () { return { delete: true }; });
  check("update memory: delete removes the entry",
        dl.deleted === true && (await c.get("n")) === undefined);
  // update on an absent key sees null and may create.
  var cr = await c.update("fresh", function (cur) { return { value: cur === null ? "created" : "x" }; });
  check("update memory: absent key seen as null", cr.value === "created" && (await c.get("fresh")) === "created");
  await c.close();

  // A committing decision can set the written value's own lifetime via
  // { value, ttlMs } — a duration the cache resolves against its own clock.
  var nowMs = 5000000;
  var ck = _newCache({ namespace: "upd-ttl", clock: function () { return nowMs; } });
  await ck.update("k", function () { return { value: "short", ttlMs: 100 }; });
  check("update memory: decision ttlMs present before expiry", (await ck.get("k")) === "short");
  nowMs += 150;
  check("update memory: decision ttlMs expired the value", (await ck.get("k")) === undefined);
  await ck.close();
}

async function testUpdateClusterCas() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cache-upd-"));
  try {
    await setupTestDb(tmpDir);
    var c = b.cache.create({ namespace: "upd-clu", backend: "cluster", ttlMs: b.constants.TIME.minutes(5) });
    await c.update("set", function (cur) { return { value: { items: (cur ? cur.items : []).concat("a") } }; });
    await c.update("set", function (cur) { return { value: { items: cur.items.concat("b") } }; });
    // Concurrent appends: the compare-and-set + retry must preserve BOTH
    // (no lost update) — the cluster race the get/set version dropped.
    await Promise.all([
      c.update("set", function (cur) { return { value: { items: cur.items.concat("x") } }; }),
      c.update("set", function (cur) { return { value: { items: cur.items.concat("y") } }; }),
    ]);
    var fin = await c.get("set");
    check("update cluster: concurrent CAS loses no write", fin.items.length === 4);
    check("update cluster: all appends present",
          fin.items.indexOf("a") !== -1 && fin.items.indexOf("b") !== -1 &&
          fin.items.indexOf("x") !== -1 && fin.items.indexOf("y") !== -1);
    var ab = await c.update("set", function () { return { abort: { stop: 1 } }; });
    check("update cluster: abort returns aborted + leaves value",
          ab.aborted && ab.aborted.stop === 1 && (await c.get("set")).items.length === 4);
    await c.update("set", function () { return { delete: true }; });
    check("update cluster: delete removes the entry", (await c.get("set")) === undefined);
    await c.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testMaxBytesEvictsLru() {
  // Cache size budget: 30 bytes. Each entry ~12 bytes JSON ("aaaaaaaa" → 10).
  var c = _newCache({
    maxBytes: 30,
    sizeOf:   function (v) { return Buffer.byteLength(String(v), "utf8"); },
  });
  await c.set("k1", "aaaaaaaa");   // 8 bytes
  await c.set("k2", "bbbbbbbb");   // 8 bytes (16 total)
  await c.set("k3", "cccccccc");   // 8 bytes (24 total)
  await c.set("k4", "dddddddd");   // 8 bytes (32 → over cap; evicts k1)
  check("maxBytes: k1 evicted (LRU)",         (await c.get("k1")) === undefined);
  check("maxBytes: k4 stored",                (await c.get("k4")) === "dddddddd");
  check("maxBytes: k2 still present",         (await c.get("k2")) === "bbbbbbbb");
  check("bytes() reflects live entries",      (await c.bytes()) <= 30 && (await c.bytes()) > 0);
  await c.close();
}

async function testMaxBytesObservabilityEmit() {
  var captured = [];
  var c = _newCache({
    maxBytes:      4,
    sizeOf:        function (v) { return v.length; },
    observability: { event: function (n, _v, l) { captured.push({ n: n, l: l }); }, tap: function (_n, _l, fn) { return fn(); } },
  });
  await c.set("a", "xx");   // 2 bytes
  await c.set("b", "xx");   // 2 bytes (full)
  await c.set("c", "xx");   // evicts oldest by bytes
  var byteEvictions = captured.filter(function (e) { return e.n === "cache.eviction.bytes"; });
  check("maxBytes: cache.eviction.bytes event fires",  byteEvictions.length >= 1);
  await c.close();
}

async function testCustomSizeOf() {
  var calls = 0;
  var c = _newCache({
    maxBytes: 20,
    sizeOf:   function (v) { calls++; return v && v.estimateBytes ? v.estimateBytes : 0; },
  });
  await c.set("k", { estimateBytes: 5 });
  check("sizeOf called",                      calls >= 1);
  check("bytes() reports custom-sized total", (await c.bytes()) === 5);
  await c.close();
}

async function testSlidingTtlMemory() {
  var nowMs = 1700000000000;
  var c = _newCache({
    ttlMs:      100,
    slidingTtl: true,
    clock:      function () { return nowMs; },
  });
  await c.set("k", "v");
  nowMs += 80;                          // 80ms elapsed
  check("sliding: read before original expiry returns value",
                                              (await c.get("k")) === "v");
  nowMs += 80;                          // 160ms total — past original 100ms; sliding bumped to ~180
  check("sliding: read after original ttl still returns",
                                              (await c.get("k")) === "v");
  nowMs += 200;                         // well past any extension
  check("sliding: eventually expires after no reads",
                                              (await c.get("k")) === undefined);
  await c.close();
}

async function testSlidingTtlOffByDefault() {
  var nowMs = 1700000000000;
  var c = _newCache({
    ttlMs: 100,
    clock: function () { return nowMs; },
  });
  await c.set("k", "v");
  nowMs += 80;
  await c.get("k");                     // would extend if sliding were on
  nowMs += 80;                          // 160ms total — past 100ms TTL
  check("sliding off: original ttl still wins",
                                              (await c.get("k")) === undefined);
  await c.close();
}

async function testTagsAndInvalidateTag() {
  var c = _newCache();
  await c.set("u-1", "alice", { tags: ["user:1", "session"] });
  await c.set("u-2", "bob",   { tags: ["user:2", "session"] });
  await c.set("u-3", "carol", { tags: ["user:3"] });

  var tags1 = await c.getTags("u-1");
  check("getTags: array length matches",     Array.isArray(tags1) && tags1.length === 2);
  check("getTags: contains user:1",          tags1.indexOf("user:1") !== -1);

  var purged = await c.invalidateTag("session");
  check("invalidateTag: returns purge count", purged === 2);
  check("invalidateTag: u-1 gone",            (await c.get("u-1")) === undefined);
  check("invalidateTag: u-2 gone",            (await c.get("u-2")) === undefined);
  check("invalidateTag: u-3 untouched",       (await c.get("u-3")) === "carol");

  // Single-key tag wipe
  var purged2 = await c.invalidateTag("user:3");
  check("invalidateTag: single-key tag",      purged2 === 1);
  await c.close();
}

async function testTagsValidateFormat() {
  var c = _newCache();
  var threw = false;
  try { await c.set("k", "v", { tags: ["", "ok"] }); } catch (_e) { threw = true; }
  check("tags: rejects empty string entry",   threw);
  threw = false;
  try { await c.set("k", "v", { tags: [42, "ok"] }); } catch (_e) { threw = true; }
  check("tags: rejects non-string entry",     threw);
  await c.close();
}

async function testInvalidateTagAuditEmit() {
  var captured = [];
  var c = _newCache({
    audit: { safeEmit: function (e) { captured.push(e); } },
  });
  await c.set("u-1", "v", { tags: ["bulk"] });
  await c.set("u-2", "v", { tags: ["bulk"] });
  await c.invalidateTag("bulk");
  var taggedAudits = captured.filter(function (e) { return e.action === "cache.tag.invalidated"; });
  check("tag invalidate audit emitted",       taggedAudits.length === 1);
  check("tag invalidate audit metadata.tag",  taggedAudits[0].metadata.tag === "bulk");
  check("tag invalidate audit count",         taggedAudits[0].metadata.itemCount === 2);
  await c.close();
}

async function testInvalidateTagOnCluster() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cache-"));
  await setupTestDb(tmpDir);
  try {
    var c = b.cache.create({
      namespace: "v411cluster",
      backend:   "cluster",
    });
    await c.set("u-1", { name: "alice" }, { tags: ["user", "tier:free"] });
    await c.set("u-2", { name: "bob" },   { tags: ["user", "tier:pro"] });
    await c.set("p-1", { sku: "x" },      { tags: ["product"] });
    check("cluster getTags returns set tags",
      JSON.stringify((await c.getTags("u-1")).sort()) === JSON.stringify(["tier:free", "user"]));
    var purged = await c.invalidateTag("user");
    check("cluster invalidateTag purges all entries with the tag", purged === 2);
    check("cluster invalidateTag dropped the tagged keys",
      (await c.get("u-1")) === undefined && (await c.get("u-2")) === undefined);
    check("cluster invalidateTag spared untagged keys",
      (await c.get("p-1")).sku === "x");
    var unpurged = await c.invalidateTag("nonexistent-tag");
    check("cluster invalidateTag returns 0 for unused tag", unpurged === 0);
    // Re-set with overlapping tag — verify multi-tag rotation on update
    await c.set("u-1", { name: "alice2" }, { tags: ["user", "tier:enterprise"] });
    check("cluster set replaces tags on update",
      JSON.stringify((await c.getTags("u-1")).sort()) === JSON.stringify(["tier:enterprise", "user"]));
    await c.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testValidationNewOpts() {
  var threw;

  threw = false;
  try { _newCache({ maxBytes: -1 }); } catch (_e) { threw = true; }
  check("validation: rejects negative maxBytes",   threw);

  threw = false;
  try { _newCache({ maxBytes: "100" }); } catch (_e) { threw = true; }
  check("validation: rejects non-number maxBytes", threw);

  threw = false;
  try { _newCache({ sizeOf: 42 }); } catch (_e) { threw = true; }
  check("validation: rejects non-fn sizeOf",       threw);

  threw = false;
  try { _newCache({ slidingTtl: "yes" }); } catch (_e) { threw = true; }
  check("validation: rejects non-bool slidingTtl", threw);
}

// ---- Uncovered-branch coverage: config-time validation ----

async function testInfinityCapsAccepted() {
  // maxEntries: Infinity and maxBytes: Infinity take the early-return
  // branch in the validators (uncapped memory backend).
  var c1 = b.cache.create({ namespace: "inf-entries", maxEntries: Infinity });
  await c1.set("k", "v");
  check("maxEntries: Infinity accepted (uncapped)", (await c1.get("k")) === "v");
  await c1.close();

  var c2 = b.cache.create({ namespace: "inf-bytes", maxBytes: Infinity });
  await c2.set("k", "v");
  check("maxBytes: Infinity accepted (uncapped)", (await c2.get("k")) === "v");
  await c2.close();
}

async function testInvalidBackendString() {
  var threwBogus = false;
  try { b.cache.create({ namespace: "n", backend: "postgres-cache" }); }
  catch (_e) { threwBogus = true; }
  check("create() with unrecognized backend string throws", threwBogus);

  // backend: "redis" with an empty-string redisUrl trips the length===0
  // arm of the redisUrl guard (distinct from the missing-url arm).
  var threwEmptyUrl = false;
  try { b.cache.create({ namespace: "n", backend: "redis", redisUrl: "" }); }
  catch (_e) { threwEmptyUrl = true; }
  check("create() backend='redis' with empty redisUrl throws", threwEmptyUrl);
}

async function testDefaultSizeOfVariants() {
  // No custom sizeOf → the framework's _defaultSizeOf runs on every set().
  // Drive the null/undefined, Buffer, and JSON-unserializable arms that the
  // existing number/object/string cases never reach.
  var c = b.cache.create({ namespace: "sizeof-default" });
  await c.set("nul", null);
  await c.set("buf", Buffer.from("hello"));
  await c.set("big", { n: 10n });        // JSON.stringify throws on BigInt → catch → 0
  check("default sizeOf: null value stored (0 bytes arm)",   (await c.get("nul")) === null);
  check("default sizeOf: Buffer value stored (length arm)",  Buffer.isBuffer(await c.get("buf")));
  check("default sizeOf: JSON-unserializable value stored (catch arm)",
        (await c.get("big")).n === 10n);
  // bytes() reflects: null=0, Buffer("hello")=5, bigint-object=0 → total 5.
  check("default sizeOf: bytes() totals the finite arms only", (await c.bytes()) === 5);
  await c.close();
}

// ---- Uncovered-branch coverage: memory has() lazy expiry ----

async function testHasExpiredEvicts() {
  var clk = b.testing.fakeClock(1_000_000);
  var captured = [];
  var c = b.cache.create({
    namespace:     "has-expired",
    ttlMs:         100,
    clock:         clk.now,
    observability: { event: function (n, _v, l) { captured.push({ n: n, l: l }); } },
  });
  await c.set("k", "v");
  clk.advance(200);   // past ttl
  check("has() on expired key returns false + lazy-evicts", (await c.has("k")) === false);
  check("has() lazy-evict emits cache.eviction.expired",
        captured.filter(function (e) { return e.n === "cache.eviction.expired"; }).length >= 1);
  // The entry is physically gone now.
  check("has() lazy-evict removed the entry", (await c.size()) === 0);
  await c.close();
}

// ---- Uncovered-branch coverage: backend-error catch on every method ----

async function testBackendErrorAllMethods() {
  var audit = b.testing.captureAudit();
  var codedErr = function () { var e = new Error("backend down"); e.code = "ECONNREFUSED"; return e; };
  var reject = function () { return Promise.reject(codedErr()); };
  var failing = {
    // required surface
    get:   reject,
    set:   reject,
    del:   reject,
    clear: reject,
    size:  reject,
    close: function () { return Promise.resolve(); },
    // optional surface — present so the wrapper forwards (rather than
    // falling back), letting the cache method's own catch fire.
    has:           reject,
    bytes:         reject,
    invalidateTag: reject,
    getTags:       reject,
  };
  var c = b.cache.create({ namespace: "fail-all", backend: failing, audit: audit });

  async function expectThrow(label, fn) {
    var threw = false;
    try { await fn(); } catch (_e) { threw = true; }
    check(label, threw);
  }
  await expectThrow("get() propagates backend error",           function () { return c.get("k"); });
  await expectThrow("set() propagates backend error",           function () { return c.set("k", "v"); });
  await expectThrow("del() propagates backend error",           function () { return c.del("k"); });
  await expectThrow("has() propagates backend error",           function () { return c.has("k"); });
  await expectThrow("clear() propagates backend error",         function () { return c.clear(); });
  await expectThrow("size() propagates backend error",          function () { return c.size(); });
  await expectThrow("bytes() propagates backend error",         function () { return c.bytes(); });
  await expectThrow("invalidateTag() propagates backend error", function () { return c.invalidateTag("t"); });
  await expectThrow("getTags() propagates backend error",       function () { return c.getTags("k"); });
  await expectThrow("wrap() propagates backend get error",      function () { return c.wrap("k", function () { return "x"; }); });

  var failedAudits = audit.byAction("cache.backend.failed");
  check("every failing method emits a cache.backend.failed audit", failedAudits.length >= 10);
  // The error's own .code rides in the audit metadata (the err.code arm).
  check("backend.failed audit carries the backend error code",
        failedAudits.some(function (e) { return e.metadata && e.metadata.code === "ECONNREFUSED"; }));
  await c.close();
}

async function testUpdateMutatorThrows() {
  // A mutatorFn that throws surfaces through backend.update as a backend
  // error — driving cache.update's catch (emit + audit + rethrow).
  var audit = b.testing.captureAudit();
  var c = b.cache.create({ namespace: "upd-throw", audit: audit });
  var threw = false;
  try {
    await c.update("k", function () { throw new Error("mutator boom"); });
  } catch (_e) { threw = true; }
  check("update() rethrows a throwing mutator", threw);
  check("update() throwing mutator emits cache.backend.failed audit",
        audit.byAction("cache.backend.failed").length === 1);
  await c.close();
}

// ---- Uncovered-branch coverage: custom-backend optional-method fallbacks ----

async function testCustomBackendOptionalFallbacks() {
  // A custom backend that implements ONLY the required surface. The
  // wrapper synthesizes has (get-and-coerce), bytes (0), invalidateTag
  // (0), getTags (null).
  var store = new Map();
  var minimal = {
    get:   function (k) { return Promise.resolve(store.get(k)); },
    set:   function (k, v) { store.set(k, v); return Promise.resolve(); },
    del:   function (k) { var ex = store.has(k); store.delete(k); return Promise.resolve(ex); },
    clear: function () { var n = store.size; store.clear(); return Promise.resolve(n); },
    size:  function () { return Promise.resolve(store.size); },
    close: function () { return Promise.resolve(); },
  };
  var c = b.cache.create({ namespace: "custom-min", backend: minimal });
  await c.set("present", "v");
  check("custom has() falls back to get-and-coerce (present → true)",  (await c.has("present")) === true);
  check("custom has() falls back to get-and-coerce (absent → false)",  (await c.has("absent")) === false);
  check("custom bytes() falls back to 0",                              (await c.bytes()) === 0);
  check("custom invalidateTag() falls back to 0",                      (await c.invalidateTag("t")) === 0);
  check("custom getTags() falls back to null",                         (await c.getTags("present")) === null);
  await c.close();
}

async function testSealRejectedOnNonCluster() {
  var c = b.cache.create({ namespace: "seal-mem" });
  var threwSet = false;
  try { await c.set("k", "v", { seal: true }); } catch (_e) { threwSet = true; }
  check("set(seal:true) on memory backend throws (cluster-only feature)", threwSet);

  var threwUpd = false;
  try { await c.update("k", function () { return { value: "v" }; }, { seal: true }); }
  catch (_e) { threwUpd = true; }
  check("update(seal:true) on memory backend throws (cluster-only feature)", threwUpd);
  await c.close();
}

async function testUpdateUnsupportedAndBadMutator() {
  // Custom backend has no atomic update → cache.update throws UNSUPPORTED.
  var store = new Map();
  var minimal = {
    get:   function (k) { return Promise.resolve(store.get(k)); },
    set:   function (k, v) { store.set(k, v); return Promise.resolve(); },
    del:   function (k) { store.delete(k); return Promise.resolve(true); },
    clear: function () { store.clear(); return Promise.resolve(0); },
    size:  function () { return Promise.resolve(store.size); },
    close: function () { return Promise.resolve(); },
  };
  var cCustom = b.cache.create({ namespace: "upd-unsupported", backend: minimal });
  var threwUnsupported = false;
  try { await cCustom.update("k", function () { return { value: 1 }; }); }
  catch (_e) { threwUnsupported = true; }
  check("update() on a custom backend without update throws UNSUPPORTED", threwUnsupported);
  await cCustom.close();

  // Non-function mutator → BAD_OPT (guarded before backend dispatch).
  var cMem = b.cache.create({ namespace: "upd-badmutator" });
  var threwBadMutator = false;
  try { await cMem.update("k", "not-a-function"); } catch (_e) { threwBadMutator = true; }
  check("update() with non-function mutator throws", threwBadMutator);
  await cMem.close();
}

async function testInvalidateTagBadArg() {
  var c = b.cache.create({ namespace: "tag-badarg" });
  var threwNonString = false;
  try { await c.invalidateTag(42); } catch (_e) { threwNonString = true; }
  check("invalidateTag(non-string) throws", threwNonString);

  var threwEmpty = false;
  try { await c.invalidateTag(""); } catch (_e) { threwEmpty = true; }
  check("invalidateTag('') throws", threwEmpty);
  await c.close();
}

async function testUpdateMemoryExpiresAtDecision() {
  // A committing decision may pin the written value's absolute expiry via
  // { value, expiresAt } — the branch distinct from the { value, ttlMs }
  // case the existing update test drives.
  var nowMs = 6_000_000;
  var c = b.cache.create({ namespace: "upd-expiresat", clock: function () { return nowMs; } });
  await c.update("k", function () { return { value: "pinned", expiresAt: nowMs + 50 }; });
  check("update decision.expiresAt honored (before expiry)", (await c.get("k")) === "pinned");
  nowMs += 100;
  check("update decision.expiresAt honored (after expiry)",  (await c.get("k")) === undefined);
  await c.close();
}

async function testObservabilitySinkThrowsSwallowed() {
  // The hot-path observability sink is drop-silent: a throwing operator
  // sink must not surface to the caller.
  var c = b.cache.create({
    namespace:     "obs-throw",
    observability: { event: function () { throw new Error("sink boom"); } },
  });
  var surfaced = false;
  try {
    await c.set("k", "v");
    await c.get("k");
  } catch (_e) { surfaced = true; }
  check("throwing observability sink is swallowed (drop-silent)", surfaced === false);
  await c.close();
}

// ---- Uncovered-branch coverage: SWR internals ----

async function testSwrInfinityTtl() {
  // SWR write path with an Infinity ttl: hard-TTL stays Infinity, no soft
  // expiry is tracked (the else arm), entry never goes stale.
  var nowMs = 1_700_000_000_000;
  var c = b.cache.create({
    namespace:            "swr-inf",
    ttlMs:                b.constants.TIME.minutes(5),
    staleWhileRevalidate: true,
    clock:                function () { return nowMs; },
  });
  var calls = 0;
  var fn = function () { calls++; return "v"; };
  await c.wrap("k", fn, { ttlMs: Infinity });
  nowMs += b.constants.TIME.days(365);
  var again = await c.wrap("k", fn, { ttlMs: Infinity });
  check("SWR Infinity ttl: value never goes stale (no recompute)",
        again === "v" && calls === 1);
  await c.close();
}

async function testSwrBackgroundRefreshFailure() {
  // Past soft TTL, the background refresh runs fn again; when that fn
  // rejects, the stale value was already served and the failure surfaces
  // only via cache.refresh.failed observability.
  var nowMs = 1_700_000_000_000;
  var captured = [];
  var c = b.cache.create({
    namespace:            "swr-refresh-fail",
    ttlMs:                100,
    staleWhileRevalidate: true,
    clock:                function () { return nowMs; },
    observability:        { event: function (n, _v, l) { captured.push({ n: n, l: l }); } },
  });
  var mode = "ok";
  var fn = function () {
    if (mode === "boom") return Promise.reject(new Error("refresh failed"));
    return Promise.resolve("fresh");
  };
  var first = await c.wrap("k", fn);
  check("SWR refresh-fail: first call computes fresh", first === "fresh");

  nowMs += 150;          // past soft (100), before hard (200)
  mode = "boom";
  var stale = await c.wrap("k", fn);   // serves stale + kicks background refresh
  check("SWR refresh-fail: serves stale while refreshing", stale === "fresh");

  await waitUntil(function () {
    return captured.filter(function (e) { return e.n === "cache.refresh.failed"; }).length >= 1;
  }, { timeoutMs: 4000, label: "swr background refresh failure emitted" });
  check("SWR refresh-fail: emits cache.refresh.failed on background error",
        captured.filter(function (e) { return e.n === "cache.refresh.failed"; }).length >= 1);
  await c.close();
}

async function testSwrWriteFailure() {
  // Under SWR, a miss computes the value then persists it through
  // _writeWithSwr; when that backend.set rejects, the failure is captured
  // via observability + audit and does not fail the wrap.
  var audit = b.testing.captureAudit();
  var readOnlyBackend = {
    get:   function () { return Promise.resolve(undefined); },   // always a miss
    set:   function () { return Promise.reject(new Error("read-only")); },
    del:   function () { return Promise.resolve(false); },
    clear: function () { return Promise.resolve(0); },
    size:  function () { return Promise.resolve(0); },
    close: function () { return Promise.resolve(); },
  };
  var c = b.cache.create({
    namespace:            "swr-write-fail",
    backend:              readOnlyBackend,
    audit:                audit,
    staleWhileRevalidate: true,
    ttlMs:                100,
  });
  var v = await c.wrap("k", function () { return "computed"; });
  check("SWR write-fail: wrap returns computed value despite failed set", v === "computed");
  await waitUntil(function () { return audit.byAction("cache.backend.failed").length >= 1; },
    { timeoutMs: 4000, label: "SWR _writeWithSwr set failure audited" });
  check("SWR write-fail: failed persist emits cache.backend.failed audit",
        audit.byAction("cache.backend.failed").length >= 1);
  await c.close();
}

async function testRedisBackendConstructs() {
  // The redis backend wires through cache-redis with a lazy connect, so
  // building + closing the instance is network-free (no op ever fires).
  // This exercises the create() redis-backend resolution branch without a
  // live server.
  var c = b.cache.create({
    namespace: "redis-construct",
    backend:   "redis",
    redisUrl:  "redis://127.0.0.1:6390/0",
  });
  check("redis backend: instance exposes get/set/close",
        typeof c.get === "function" && typeof c.set === "function" && typeof c.close === "function");
  check("redis backend: resolved as a custom-wrapped backend", c._backend && c._backend.name === "custom");
  await c.close();   // never connected — close is a no-op teardown
}

async function testWrapSetFailureNonSwr() {
  // Non-SWR wrap: a miss computes the value, then the backend.set rejects.
  // The wrap still resolves to the computed value (failed write doesn't
  // fail the wrap) but emits cache.backend.failed.
  var audit = b.testing.captureAudit();
  var readOnlyBackend = {
    get:   function () { return Promise.resolve(undefined); },   // always a miss
    set:   function () { return Promise.reject(new Error("read-only")); },
    del:   function () { return Promise.resolve(false); },
    clear: function () { return Promise.resolve(0); },
    size:  function () { return Promise.resolve(0); },
    close: function () { return Promise.resolve(); },
  };
  var c = b.cache.create({ namespace: "wrap-set-fail", backend: readOnlyBackend, audit: audit });
  var v = await c.wrap("k", function () { return "computed"; });
  check("wrap: computed value returned despite failed backend write", v === "computed");
  check("wrap: failed backend write emits cache.backend.failed audit",
        audit.byAction("cache.backend.failed").length >= 1);
  await c.close();
}

// ---- Uncovered-branch coverage: cross-node invalidation via pubsub ----

async function testMemoryInfinityWriteArms() {
  // The Infinity-lifetime arm of set / update / wrap expiry resolution
  // (expiresAt = Infinity rather than clock()+ttlMs), plus getTags on an
  // entry stored without any tags (the empty-array arm).
  var c = b.cache.create({ namespace: "inf-arms", ttlMs: 100 });
  await c.set("s", "v", { ttlMs: Infinity });
  check("set(ttlMs:Infinity): getTags on an untagged entry returns []",
        Array.isArray(await c.getTags("s")) && (await c.getTags("s")).length === 0);

  await c.update("u", function () { return { value: 1 }; }, { ttlMs: Infinity });
  check("update(ttlMs:Infinity): value written", (await c.get("u")) === 1);

  var w = await c.wrap("w", function () { return "computed"; }, { ttlMs: Infinity });
  check("wrap(ttlMs:Infinity): value computed + cached", w === "computed" && (await c.get("w")) === "computed");
  await c.close();
}

async function testClusterInfinityAndEmptyClear() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cache-infclu-"));
  try {
    await setupTestDb(tmpDir);
    var c = b.cache.create({ namespace: "cb-inf", backend: "cluster", ttlMs: 100 });
    // clear() over an empty namespace: rowCount is falsy → the `|| 0` arm.
    check("cluster clear on empty namespace returns 0", (await c.clear()) === 0);

    await c.set("s", { forever: true }, { ttlMs: Infinity });   // storedExpires = MAX_SAFE arm
    check("cluster set(ttlMs:Infinity): value round-trips", (await c.get("s")).forever === true);

    await c.update("u", function () { return { value: "kept" }; }, { ttlMs: Infinity });
    check("cluster update(ttlMs:Infinity): value written", (await c.get("u")) === "kept");
    await c.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testInvalidationPubsubBadShape() {
  var threw = false;
  try {
    b.cache.create({ namespace: "bad-ps", invalidationPubsub: { publish: function () {} } });
  } catch (_e) { threw = true; }
  check("create() rejects an invalidationPubsub missing subscribe/unsubscribe", threw);
}

async function testInvalidationPubsubCrossNode() {
  var ps = b.pubsub.create({ backend: "local" });
  // Two memory-backed instances sharing one namespace + pubsub simulate two
  // nodes: a mutation on one mirrors to the other's local store.
  var nodeA = b.cache.create({ namespace: "xnode", invalidationPubsub: ps });
  var nodeB = b.cache.create({ namespace: "xnode", invalidationPubsub: ps });
  try {
    // del propagation
    await nodeB.set("k", "v");
    await nodeA.del("k");
    await waitUntil(async function () { return (await nodeB.get("k")) === undefined; },
      { timeoutMs: 4000, label: "cross-node del propagates to nodeB" });
    check("cross-node del propagates", (await nodeB.get("k")) === undefined);

    // tag propagation
    await nodeB.set("t1", "v", { tags: ["grp"] });
    await nodeA.invalidateTag("grp");
    await waitUntil(async function () { return (await nodeB.get("t1")) === undefined; },
      { timeoutMs: 4000, label: "cross-node invalidateTag propagates to nodeB" });
    check("cross-node invalidateTag propagates", (await nodeB.get("t1")) === undefined);

    // clear propagation
    await nodeB.set("c1", "v");
    await nodeB.set("c2", "v");
    await nodeA.clear();
    await waitUntil(async function () { return (await nodeB.size()) === 0; },
      { timeoutMs: 4000, label: "cross-node clear propagates to nodeB" });
    check("cross-node clear propagates", (await nodeB.size()) === 0);
  } finally {
    await nodeA.close();   // exercises the pubsub unsubscribe-on-close path
    await nodeB.close();
    if (ps.close) await ps.close();
  }
}

// ---- Uncovered-branch coverage: cluster sliding TTL / seal / sweep ----

async function testClusterSlidingTtl() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cache-slide-"));
  try {
    await setupTestDb(tmpDir);
    var nowMs = 2_000_000;
    var c = b.cache.create({
      namespace:  "cb-slide",
      backend:    "cluster",
      ttlMs:      100,
      slidingTtl: true,
      clock:      function () { return nowMs; },
    });
    await c.set("k", "v");     // expiresAt = 2_000_100
    nowMs += 80;               // clock 2_000_080
    // This read fires the best-effort sliding extension: expiresAt →
    // 2_000_080 + 100 = 2_000_180 (a fire-and-forget UPDATE).
    check("cluster sliding: read before original expiry returns", (await c.get("k")) === "v");
    // Advance PAST the original 100ms expiry but before the extended one.
    // has() (a non-mutating select honoring expiresAt) becomes true only
    // once the extension UPDATE has committed — a deterministic signal that
    // the slide landed, with no lazy-purge / re-slide side effects.
    nowMs = 2_000_150;
    await waitUntil(async function () { return (await c.has("k")) === true; },
      { timeoutMs: 2000, label: "cluster sliding extension committed past original ttl" });
    check("cluster sliding: read after original ttl still returns (extended)",
          (await c.get("k")) === "v");
    await c.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClusterSealAndUpdateLifetimes() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cache-seal-"));
  try {
    await setupTestDb(tmpDir);
    var nowMs = 3_000_000;
    var c = b.cache.create({
      namespace: "cb-seal",
      backend:   "cluster",
      ttlMs:     b.constants.TIME.minutes(5),
      clock:     function () { return nowMs; },
    });
    // Sealed write + sealed read (marker-prefix encode/decode path).
    await c.set("s", { secret: "top" }, { seal: true });
    check("cluster seal: sealed value round-trips", (await c.get("s")).secret === "top");

    // Atomic update over the sealed row: reads+unseals current, reseals new.
    var r = await c.update("s", function (cur) {
      return { value: { secret: (cur && cur.secret) + "!" }, seal: true };
    }, { seal: true });
    check("cluster seal: update over sealed row reseals",
          r.updated === true && (await c.get("s")).secret === "top!");

    // update decision that pins the written value's own lifetime.
    await c.update("ttlkey", function () { return { value: "short", ttlMs: 100 }; });
    check("cluster update decision.ttlMs: present before expiry", (await c.get("ttlkey")) === "short");

    await c.update("expkey", function () { return { value: "pinned", expiresAt: nowMs + 100 }; });
    check("cluster update decision.expiresAt: present before expiry", (await c.get("expkey")) === "pinned");

    nowMs += 200;
    check("cluster update decision.ttlMs: expired after advance",     (await c.get("ttlkey")) === undefined);
    check("cluster update decision.expiresAt: expired after advance", (await c.get("expkey")) === undefined);
    await c.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClusterBytesReturnsZero() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cache-bytes-"));
  try {
    await setupTestDb(tmpDir);
    var c = b.cache.create({ namespace: "cb-bytes", backend: "cluster" });
    // The cluster backend does not track byte accounting → bytes() → 0.
    check("cluster bytes() returns 0 (no byte accounting)", (await c.bytes()) === 0);
    await c.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testMemorySweepTimerFires() {
  // The periodic sweep purges expired entries and emits one
  // cache.eviction.expired per purged key. Uses the real timer (minimum
  // 1000ms cadence) with real wall-clock TTL so entries are expired when
  // the sweep runs; polls the observability signal.
  var captured = [];
  var c = b.cache.create({
    namespace:       "mem-sweep",
    ttlMs:           100,            // real-clock 100ms — expired well before first sweep
    sweepIntervalMs: 1000,
    observability:   { event: function (n, _v, l) { captured.push({ n: n, l: l }); } },
  });
  try {
    await c.set("a", 1);
    await c.set("b", 2);
    // Do NOT read — let the sweep timer, not lazy purge, do the eviction.
    await waitUntil(function () {
      return captured.filter(function (e) { return e.n === "cache.eviction.expired"; }).length >= 2;
    }, { timeoutMs: 5000, label: "memory sweep timer purges expired entries" });
    check("memory sweep timer emits cache.eviction.expired for purged entries",
          captured.filter(function (e) { return e.n === "cache.eviction.expired"; }).length >= 2);
  } finally {
    await c.close();
  }
}

async function testClusterSweepTimerFires() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-cache-sweep-"));
  try {
    await setupTestDb(tmpDir);
    var c = b.cache.create({
      namespace:       "cb-sweep",
      backend:         "cluster",
      ttlMs:           100,          // real-clock 100ms
      sweepIntervalMs: 1000,
    });
    // Tag rows are read without an expiry filter, so getTags keeps returning
    // the tag until the sweep physically deletes the junction row — a clean
    // signal that the sweep DELETE (not lazy purge) ran.
    await c.set("k", "v", { tags: ["swept"] });
    check("cluster sweep: tag present before sweep", (await c.getTags("k")).length === 1);
    await waitUntil(async function () { return (await c.getTags("k")).length === 0; },
      { timeoutMs: 5000, label: "cluster sweep timer deletes expired rows + tags" });
    check("cluster sweep timer deletes expired rows + their tag rows",
          (await c.getTags("k")).length === 0);
    await c.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function run() {
  await testSurface();
  await testValidation();
  await testGetSetDel();
  await testTtlExpiration();
  await testPerCallTtlOverride();
  await testInfinityTtl();
  await testZeroTtl();
  await testLruEvictionOnSize();
  await testLruRecencyBumpOnGet();
  await testHasDoesNotBumpRecency();
  await testSweepTimer();
  await testClear();
  await testWrapBasic();
  await testWrapSingleFlight();
  await testWrapSingleFlightOptOut();
  await testWrapPerCallTtl();
  await testStaleWhileRevalidate();
  await testAuditClearedOn();
  await testAuditClearedOptOut();
  await testAuditCarriesActorContext();
  await testAuditBackendFailed();
  await testAuditFailuresOptOut();
  await testCustomBackend();
  await testClosedState();
  await testObservabilityEmission();
  await testObservabilityWrapCompute();
  await testClusterBackendBasics();
  await testClusterNamespaceIsolation();
  await testClusterTtlExpiration();
  await testUpdateMemory();
  await testUpdateClusterCas();

  // v0.4.11
  await testValidationNewOpts();
  await testMaxBytesEvictsLru();
  await testMaxBytesObservabilityEmit();
  await testCustomSizeOf();
  await testSlidingTtlMemory();
  await testSlidingTtlOffByDefault();
  await testTagsAndInvalidateTag();
  await testTagsValidateFormat();
  await testInvalidateTagAuditEmit();
  await testInvalidateTagOnCluster();

  // Uncovered-branch coverage sweep
  await testInfinityCapsAccepted();
  await testInvalidBackendString();
  await testDefaultSizeOfVariants();
  await testHasExpiredEvicts();
  await testBackendErrorAllMethods();
  await testUpdateMutatorThrows();
  await testCustomBackendOptionalFallbacks();
  await testSealRejectedOnNonCluster();
  await testUpdateUnsupportedAndBadMutator();
  await testInvalidateTagBadArg();
  await testUpdateMemoryExpiresAtDecision();
  await testObservabilitySinkThrowsSwallowed();
  await testSwrInfinityTtl();
  await testSwrBackgroundRefreshFailure();
  await testSwrWriteFailure();
  await testRedisBackendConstructs();
  await testWrapSetFailureNonSwr();
  await testMemoryInfinityWriteArms();
  await testClusterInfinityAndEmptyClear();
  await testInvalidationPubsubBadShape();
  await testInvalidationPubsubCrossNode();
  await testClusterSlidingTtl();
  await testClusterSealAndUpdateLifetimes();
  await testClusterBytesReturnsZero();
  await testMemorySweepTimerFires();
  await testClusterSweepTimerFires();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
