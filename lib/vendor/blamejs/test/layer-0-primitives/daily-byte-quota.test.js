"use strict";
/**
 * b.middleware.dailyByteQuota — per-IP rolling 24-hour byte budget tests.
 *
 * Run standalone: `node test/layer-0-primitives/daily-byte-quota.test.js`
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _mockReq(opts) {
  opts = opts || {};
  return {
    ip:      opts.ip      || "10.0.0.1",
    method:  opts.method  || "GET",
    url:     opts.url     || "/",
    headers: opts.headers || {},
    socket:  opts.socket  || { remoteAddress: opts.ip || "10.0.0.1" },
  };
}

function _mockRes() {
  var captured = { status: 0, body: null, ended: false };
  var listeners = {};
  return {
    writableEnded: false,
    statusCode:    200,
    writeHead: function (status, headers) {
      captured.status = status;
      captured.headers = headers;
    },
    write: function (chunk, encoding, cb) {
      if (typeof cb === "function") cb();
      return true;
    },
    end: function (chunk, encoding, cb) {
      captured.body = chunk;
      captured.ended = true;
      this.writableEnded = true;
      if (typeof cb === "function") cb();
      if (typeof encoding === "function") encoding();
    },
    setHeader: function () {},
    on: function (e, cb) { listeners[e] = cb; },
    _captured: captured,
  };
}

async function _drive(mw, req, res) {
  // Hung-detection: the middleware is given a real-time window to either call
  // next() or end the response; whichever happened decides the outcome. This
  // is a verify-over-a-window observation (we let the full window elapse to
  // see what the middleware did), so passiveObserve is the right primitive —
  // it clears its own timer when the window completes, leaving nothing behind.
  var nextCalled = false;
  mw(req, res, function () { nextCalled = true; });
  await helpers.passiveObserve(200, "daily-byte-quota: middleware-hung detection window");   // allow:raw-byte-literal — detection window ms
  if (nextCalled) return "next";
  return res._captured.ended ? "next" : "hung";
}

async function testQuotaBelowLimitPasses() {
  var quota = b.middleware.dailyByteQuota({
    bytesPerDay: b.constants.BYTES.kib(10),
    audit:       false,
  });
  var req = _mockReq({ headers: { "content-length": "100" } });
  var res = _mockRes();
  var rv = await _drive(quota, req, res);
  check("under-quota request passes", rv === "next");
}

async function testQuotaAboveLimitRefuses() {
  var quota = b.middleware.dailyByteQuota({
    bytesPerDay: b.constants.BYTES.kib(1),
    audit:       false,
  });
  var req = _mockReq({ headers: { "content-length": String(b.constants.BYTES.kib(2)) } });
  var res = _mockRes();
  // First call drains over quota.
  await _drive(quota, req, res);
  // Account by simulating end (write happens through patched res.end).
  res.end("body", "utf8");
  // Second call should be refused.
  var req2 = _mockReq({ ip: "10.0.0.1" });
  var res2 = _mockRes();
  await _drive(quota, req2, res2);
  check("over-quota refused with 429", res2._captured.status === 429);
  check("over-quota response has Retry-After", res2._captured.headers && res2._captured.headers["Retry-After"]);
}

async function testGetKeyOverride() {
  var seen = [];
  var quota = b.middleware.dailyByteQuota({
    bytesPerDay: b.constants.BYTES.gib(1),
    audit:       false,
    getKey:      function (req) { seen.push(req.headers["x-tenant"]); return req.headers["x-tenant"] || null; },
  });
  var req = _mockReq({ headers: { "x-tenant": "acme" } });
  var res = _mockRes();
  await _drive(quota, req, res);
  check("getKey called with req",       seen.length === 1);
  check("getKey returned tenant value", seen[0] === "acme");
}

async function testNullKeyBypassesQuota() {
  // When getKey returns null, the request bypasses the quota
  // (operator's getKey decided this IP is out-of-scope).
  var quota = b.middleware.dailyByteQuota({
    bytesPerDay: 1,
    audit:       false,
    getKey:      function () { return null; },
  });
  var req = _mockReq();
  var res = _mockRes();
  var rv = await _drive(quota, req, res);
  check("null key bypasses quota", rv === "next");
}

function testCreateRefusesBadQuota() {
  var threw = false;
  try { b.middleware.dailyByteQuota({ bytesPerDay: 0, audit: false }); }
  catch (e) { threw = e.code === "daily-byte-quota/bad-quota"; }
  check("create refuses bytesPerDay=0", threw);
  var threw2 = false;
  try { b.middleware.dailyByteQuota({ bytesPerDay: -100, audit: false }); }
  catch (e) { threw2 = e.code === "daily-byte-quota/bad-quota"; }
  check("create refuses negative bytesPerDay", threw2);
  var threw3 = false;
  try { b.middleware.dailyByteQuota({ bytesPerDay: Infinity, audit: false }); }
  catch (e) { threw3 = e.code === "daily-byte-quota/bad-quota"; }
  check("create refuses Infinity bytesPerDay", threw3);
}

function testSkipPathsBypass() {
  var quota = b.middleware.dailyByteQuota({
    bytesPerDay: 1,
    audit:       false,
    skipPaths:   ["/healthz", /^\/metrics/],
  });
  var seen = [];
  function _next() { seen.push("called"); }
  // skipPaths shape covered by middleware logic — verify bypass works.
  quota(_mockReq({ url: "/healthz" }), _mockRes(), _next);
  quota(_mockReq({ url: "/metrics/foo" }), _mockRes(), _next);
  check("skipPaths bypass calls next", seen.length === 2);
}

async function run() {
  await testQuotaBelowLimitPasses();
  await testQuotaAboveLimitRefuses();
  await testGetKeyOverride();
  await testNullKeyBypassesQuota();
  testCreateRefusesBadQuota();
  testSkipPathsBypass();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(function () { console.log("OK — daily-byte-quota tests"); })
       .catch(function (e) { console.error(e); process.exit(1); });
}
