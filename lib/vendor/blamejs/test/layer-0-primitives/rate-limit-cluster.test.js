"use strict";
/**
 * rate-limit — cluster-shared backend.
 *
 * The middleware now exposes a backend seam:
 *   - 'memory' (default) — token bucket, in-process, sync take().
 *   - 'cluster'          — fixed-window counter shared via
 *                          _blamejs_rate_limit_counters; multi-process
 *                          accurate. take() is async.
 *
 * Operators can also pass a custom { take, reset } object.
 *
 * Run standalone: `node test/layer-0-primitives/rate-limit-cluster.test.js`
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
var _mockReq       = helpers._mockReq;
var _mockRes       = helpers._mockRes;

function _waitMicrotasks(n) {
  var p = Promise.resolve();
  for (var i = 0; i < (n || 5); i++) p = p.then(function () { return new Promise(function (r) { setImmediate(r); }); });
  return p;
}

async function testClusterBackendBasicLimit() {
  // limit=3 / windowMs=10s → first 3 requests pass, 4th blocked.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-rl-"));
  try {
    await setupTestDb(tmpDir);
    var mw = b.middleware.rateLimit({
      backend:  "cluster",
      limit:    3,
      windowMs: 10000,
    });

    async function fire() {
      var req = _mockReq();
      var res = _mockRes();
      var nextCalled = false;
      mw(req, res, function () { nextCalled = true; });
      await _waitMicrotasks(3);
      return { passed: nextCalled, status: res._captured().status };
    }

    check("cluster: 1st request passes",          (await fire()).passed);
    check("cluster: 2nd request passes",          (await fire()).passed);
    check("cluster: 3rd request passes",          (await fire()).passed);
    var blocked = await fire();
    check("cluster: 4th request blocked with 429",
                                                  !blocked.passed && blocked.status === 429);

    // The DB row is what's authoritative — verify count == 4.
    var row = b.db.prepare(
      "SELECT count FROM _blamejs_rate_limit_counters"
    ).get();
    check("cluster: counter row reflects 4 takes", row && row.count === 4);

    mw.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClusterBackendIndependentKeys() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-rl-"));
  try {
    await setupTestDb(tmpDir);
    var mw = b.middleware.rateLimit({
      backend:  "cluster",
      limit:    2,
      windowMs: 10000,
      keyFn:    function (req) { return req.headers["x-key"] || "default"; },
    });

    async function fireKey(k) {
      var req = _mockReq({ headers: { "x-key": k } });
      var res = _mockRes();
      var ok = false;
      mw(req, res, function () { ok = true; });
      await _waitMicrotasks(3);
      return ok;
    }

    check("cluster: keyA 1st passes",            await fireKey("a"));
    check("cluster: keyA 2nd passes",            await fireKey("a"));
    check("cluster: keyA 3rd blocked",          !(await fireKey("a")));
    check("cluster: keyB independent — passes",  await fireKey("b"));
    check("cluster: keyB independent — passes",  await fireKey("b"));
    check("cluster: keyB 3rd blocked",          !(await fireKey("b")));

    mw.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClusterBackendWindowRollover() {
  // Use opts.date / time injection? The backend computes windowStart
  // from Date.now(), so to test rollover deterministically we directly
  // manipulate the DB row to look like a stale window, then verify
  // the next take resets count to 1.
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-rl-"));
  try {
    await setupTestDb(tmpDir);
    var mw = b.middleware.rateLimit({
      backend:  "cluster",
      limit:    2,
      windowMs: 10000,
    });

    async function fire() {
      var req = _mockReq();
      var res = _mockRes();
      var ok = false;
      mw(req, res, function () { ok = true; });
      await _waitMicrotasks(3);
      return ok;
    }

    // Burn through the limit
    await fire(); await fire();
    check("rollover: 3rd in same window blocked",  !(await fire()));

    // Fast-forward: rewrite the row so its windowStart is well in the past.
    b.db.prepare(
      "UPDATE _blamejs_rate_limit_counters SET windowStart = ?, count = ?"
    ).run(Date.now() - 60000, 99);

    // The next take's INSERT...ON CONFLICT sees an older windowStart
    // and rolls count back to 1 → request passes.
    check("rollover: stale window → request passes",  await fire());
    var row = b.db.prepare(
      "SELECT count FROM _blamejs_rate_limit_counters"
    ).get();
    check("rollover: counter reset to 1",            row.count === 1);

    mw.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testClusterBackendAuditEmit() {
  var tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "blamejs-rl-"));
  try {
    await setupTestDb(tmpDir);
    var mw = b.middleware.rateLimit({
      backend:  "cluster",
      limit:    1,
      windowMs: 10000,
    });

    async function fire() {
      var req = _mockReq();
      var res = _mockRes();
      var ok = false;
      mw(req, res, function () { ok = true; });
      await _waitMicrotasks(3);
      return ok;
    }
    await fire();   // pass
    await fire();   // block
    await b.audit.flush();

    var blocked = await b.audit.query({ action: "system.ratelimit.block" });
    check("audit: ratelimit.block emitted on cluster block", blocked.length === 1);

    mw.close();
  } finally {
    await teardownTestDb(tmpDir);
  }
}

async function testCustomBackendObject() {
  var calls = [];
  var custom = {
    take: function (key, cost) {
      calls.push({ key: key, cost: cost });
      return Promise.resolve({
        allowed: calls.length <= 2,
        limit: 2,
        remaining: Math.max(0, 2 - calls.length),
        retryAfter: calls.length > 2 ? 5 : 0,
      });
    },
    reset: function () { return Promise.resolve(); },
    close: function () {},
  };

  var mw = b.middleware.rateLimit({ backend: custom });
  async function fire() {
    var req = _mockReq();
    var res = _mockRes();
    var ok = false;
    mw(req, res, function () { ok = true; });
    await _waitMicrotasks(3);
    return ok;
  }
  check("custom backend: 1st passes",           await fire());
  check("custom backend: 2nd passes",           await fire());
  check("custom backend: 3rd blocked",          !(await fire()));
  check("custom backend: take called 3 times",  calls.length === 3);
}

async function testUnknownBackendRejected() {
  var threw = null;
  try {
    b.middleware.rateLimit({ backend: "redis" });
  } catch (e) { threw = e; }
  check("unknown backend rejected at create()",
        threw && /unknown backend/.test(threw.message));
}

async function testFailOpenOnBackendError() {
  // If the backend throws, the middleware fails open (calls next)
  // rather than crashing the request path.
  var custom = {
    take: function () { return Promise.reject(new Error("backend dead")); },
    reset: function () { return Promise.resolve(); },
    close: function () {},
  };
  var mw = b.middleware.rateLimit({ backend: custom });
  var req = _mockReq();
  var res = _mockRes();
  var ok = false;
  mw(req, res, function () { ok = true; });
  await _waitMicrotasks(3);
  check("backend error → middleware fails open",  ok === true);
}

async function run() {
  await testClusterBackendBasicLimit();
  await testClusterBackendIndependentKeys();
  await testClusterBackendWindowRollover();
  await testClusterBackendAuditEmit();
  await testCustomBackendObject();
  await testUnknownBackendRejected();
  await testFailOpenOnBackendError();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}
