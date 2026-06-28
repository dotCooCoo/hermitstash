"use strict";
/**
 * b.network.byteQuota — standalone preflight (check) + commit (record)
 * primitive. Operators with handlers that already know the byte cost of an
 * op call check/record directly without going through the middleware.
 *
 * Run standalone: `node test/layer-0-primitives/network-byte-quota.test.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

async function testCheckBelowQuotaPasses() {
  var q = b.network.byteQuota.create({ bytesPerDay: b.constants.BYTES.kib(10), audit: false });
  var v = await q.check("10.0.0.1", b.constants.BYTES.kib(1));
  check("check under quota allowed",          v.allowed === true);
  check("check returns remaining headroom",   v.remaining === b.constants.BYTES.kib(9));
  check("check carries quota field",          v.quota === b.constants.BYTES.kib(10));
  check("check non-degraded on memory backend", v.degraded === false);
}

async function testCheckOverQuotaRefuses() {
  var q = b.network.byteQuota.create({ bytesPerDay: b.constants.BYTES.kib(1), audit: false });
  var v = await q.check("10.0.0.1", b.constants.BYTES.kib(2));
  check("check over quota denied",          v.allowed === false);
  check("check denial carries retryAfter",  v.retryAfterSec > 0);
}

async function testCheckIsPureNonMutating() {
  // Verify check() doesn't mutate the counter — multiple checks at the
  // same byte count must all succeed when no record() has been called.
  var q = b.network.byteQuota.create({ bytesPerDay: b.constants.BYTES.kib(10), audit: false });
  await q.check("10.0.0.1", b.constants.BYTES.kib(5));
  await q.check("10.0.0.1", b.constants.BYTES.kib(5));
  await q.check("10.0.0.1", b.constants.BYTES.kib(5));
  var snap = await q.snapshot();
  // No record calls — total stays 0.
  check("check is non-mutating", snap.length === 0 || snap[0].total === 0);
}

async function testRecordCommitsBytes() {
  var q = b.network.byteQuota.create({ bytesPerDay: b.constants.BYTES.kib(10), audit: false });
  await q.record("10.0.0.1", b.constants.BYTES.kib(3));
  await q.record("10.0.0.1", b.constants.BYTES.kib(2));
  var v = await q.check("10.0.0.1", b.constants.BYTES.kib(1));
  check("record cumulates",                    v.total === b.constants.BYTES.kib(5));
  // verdict.remaining is post-projection — total + requested = 6KiB; quota - 6 = 4 KiB headroom left.
  check("subsequent check reflects committed", v.remaining === b.constants.BYTES.kib(4));
}

async function testCheckThenRecordRoundtrip() {
  // Operator pattern — check before accept, record after success.
  var q = b.network.byteQuota.create({ bytesPerDay: b.constants.BYTES.kib(10), audit: false });
  var preflight = await q.check("10.0.0.1", b.constants.BYTES.kib(7));
  check("preflight allowed", preflight.allowed === true);
  await q.record("10.0.0.1", b.constants.BYTES.kib(7));
  var preflight2 = await q.check("10.0.0.1", b.constants.BYTES.kib(7));
  check("second 7KiB rejected after first committed", preflight2.allowed === false);
}

async function testResetClearsCounter() {
  var q = b.network.byteQuota.create({ bytesPerDay: b.constants.BYTES.kib(10), audit: false });
  await q.record("10.0.0.1", b.constants.BYTES.kib(8));
  await q.reset("10.0.0.1");
  var v = await q.check("10.0.0.1", b.constants.BYTES.kib(8));
  check("reset clears the per-key counter", v.allowed === true && v.total === 0);
}

async function testSnapshotShape() {
  var q = b.network.byteQuota.create({ bytesPerDay: b.constants.BYTES.kib(10), audit: false });
  await q.record("10.0.0.1", b.constants.BYTES.kib(2));
  await q.record("10.0.0.2", b.constants.BYTES.kib(5));
  var rows = await q.snapshot();
  var keys = rows.map(function (r) { return r.key; }).sort();
  check("snapshot lists every accounted key", keys.length === 2 && keys[0] === "10.0.0.1" && keys[1] === "10.0.0.2");
  check("snapshot row carries quota + remaining",
    rows[0].quota === b.constants.BYTES.kib(10) && typeof rows[0].remaining === "number");
}

function testCreateRefusesBadQuota() {
  var threw = false;
  try { b.network.byteQuota.create({ bytesPerDay: 0 }); } catch (e) { threw = e.code === "byte-quota/bad-quota"; }
  check("create throws on bytesPerDay=0", threw);
  var threw2 = false;
  try { b.network.byteQuota.create({ bytesPerDay: -1 }); } catch (e) { threw2 = e.code === "byte-quota/bad-quota"; }
  check("create throws on negative quota", threw2);
  var threw3 = false;
  try { b.network.byteQuota.create({ bytesPerDay: Infinity }); } catch (e) { threw3 = e.code === "byte-quota/bad-quota"; }
  check("create throws on non-finite quota", threw3);
}

async function testCheckRejectsBadKey() {
  var q = b.network.byteQuota.create({ bytesPerDay: b.constants.BYTES.kib(10), audit: false });
  var threw = false;
  try { await q.check("", 100); } catch (e) { threw = e.code === "byte-quota/bad-key"; }
  check("check throws on empty key", threw);
  var threw2 = false;
  try { await q.check("k", -1); } catch (e) { threw2 = e.code === "byte-quota/bad-bytes"; }
  check("check throws on negative bytes", threw2);
  var threw3 = false;
  try { await q.record("k", Infinity); } catch (e) { threw3 = e.code === "byte-quota/bad-bytes"; }
  check("record throws on non-finite bytes", threw3);
}

async function testRefusalEmitsAudit() {
  // Composing through audit.safeEmit — refusal emits network.byte_quota.exceeded.
  var seen = [];
  var origSafeEmit = b.audit.safeEmit;
  b.audit.safeEmit = function (evt) { seen.push(evt); };
  try {
    var q = b.network.byteQuota.create({ bytesPerDay: 100, audit: true });
    await q.check("10.0.0.1", 9999);
  } finally {
    b.audit.safeEmit = origSafeEmit;
  }
  var hit = seen.some(function (e) { return e.action === "network.byte_quota.exceeded"; });
  check("refusal emits network.byte_quota.exceeded", hit);
}

async function testConcurrentRecordLosesNoBytesOnCacheBackend() {
  // RED before the fix: the cache backend's account() did a non-atomic
  // get → mutate → set, so concurrent record() calls for the same key all read
  // the same counter and clobbered each other (lost update), letting a peer's
  // rolling byte total stay under quota and bypass the limit on the shared
  // (cluster) cache path. The memory backend is single-writer-synchronous and
  // safe; the bug is cache-only. The fix routes account() through the cache's
  // atomic compare-and-set update(), so every concurrent charge is counted.
  var cache = b.cache.create({ backend: "memory", namespace: "bq-race", ttlMs: 86400000, maxEntries: 1000 });
  var q = b.network.byteQuota.create({ bytesPerDay: b.constants.BYTES.mib(100), cache: cache, audit: false });
  var N = 20, per = b.constants.BYTES.kib(1);
  var jobs = [];
  for (var i = 0; i < N; i++) jobs.push(q.record("10.0.0.9", per));
  await Promise.all(jobs);
  var v = await q.check("10.0.0.9", 0);
  check("concurrent record() on the cache backend loses no bytes (atomic RMW)",
        v.total === N * per);
}

async function testRecordSurfacesUnsupportedCacheLoud() {
  // A b.cache exposes update() for every instance, but a backend that can't do
  // atomic RMW (get/set-only) throws UNSUPPORTED at call time. Under record()'s
  // drop-silent policy that would silently disable the quota — it must surface
  // loud so the operator fixes the cache backend.
  var cache = {
    get: async function () { return undefined; },
    set: async function () {},
    update: async function () { var e = new Error("backend has no atomic update"); e.code = "UNSUPPORTED"; throw e; },
  };
  var q = b.network.byteQuota.create({ bytesPerDay: b.constants.BYTES.kib(10), cache: cache, audit: false });
  var threw = null;
  try { await q.record("10.0.0.1", 100); } catch (e) { threw = e.code; }
  check("record() throws loud on a cache backend without atomic update (no silent disable)",
        threw === "byte-quota/cache-no-atomic-update");
}

async function testRecordRetriesUnderCacheContention() {
  // The cluster cache's CAS throws UPDATE_CONTENTION after exhausting its own
  // retries. A burst must not drop a charge (that lets a peer undercount), so
  // record() retries the whole RMW. This cache throws contention several times,
  // then commits — the charge must still land.
  var store = new Map();
  var failsLeft = 4;
  var cache = {
    get: async function (k) { return store.get(k); },
    set: async function (k, v) { store.set(k, v); },
    update: async function (k, fn) {
      if (failsLeft > 0) { failsLeft -= 1; var e = new Error("write contention"); e.code = "UPDATE_CONTENTION"; throw e; }
      var dec = fn(store.get(k));
      store.set(k, dec.value);
      return { updated: true, value: dec.value };
    },
  };
  var q = b.network.byteQuota.create({ bytesPerDay: b.constants.BYTES.kib(10), cache: cache, audit: false });
  await q.record("10.0.0.1", b.constants.BYTES.kib(3));
  var v = await q.check("10.0.0.1", 0);
  check("record() retries cache contention and still commits the charge",
        v.total === b.constants.BYTES.kib(3) && failsLeft === 0);
}

async function run() {
  await testCheckBelowQuotaPasses();
  await testCheckOverQuotaRefuses();
  await testCheckIsPureNonMutating();
  await testRecordCommitsBytes();
  await testCheckThenRecordRoundtrip();
  await testResetClearsCounter();
  await testSnapshotShape();
  testCreateRefusesBadQuota();
  await testCheckRejectsBadKey();
  await testRefusalEmitsAudit();
  await testConcurrentRecordLosesNoBytesOnCacheBackend();
  await testRecordSurfacesUnsupportedCacheLoud();
  await testRecordRetriesUnderCacheContention();
  console.log("OK — network-byte-quota tests");
}

module.exports = { run: run };
if (require.main === module) run().catch(function (e) { console.error(e); process.exit(1); });
