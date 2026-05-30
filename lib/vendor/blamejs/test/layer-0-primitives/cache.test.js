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
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}
