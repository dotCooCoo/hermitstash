/**
 * Load tests using autocannon.
 * Tests concurrent request handling, memory stability, and response times.
 */
var { describe, it, before, after } = require("node:test");
var assert = require("node:assert");

var testServer = require("../helpers/test-server");

before(async function () {
  await testServer.start();
});

after(function () { return testServer.stop(); });

describe("load tests", function () {
  it("handles 100 concurrent GET /auth/login requests", async function () {
    var autocannon = require("autocannon");
    var result = await autocannon({
      url: testServer.baseUrl() + "/auth/login",
      connections: 10,
      amount: 100,
      timeout: 10,
    });
    assert.strictEqual(result.non2xx, 0, "all requests should return 2xx, got " + result.non2xx + " non-2xx");
    assert.ok(result.latency.p99 < 1000, "p99 latency should be under 1s, got " + result.latency.p99 + "ms");
  });

  it("handles 50 concurrent GET /drop requests", async function () {
    var autocannon = require("autocannon");
    var result = await autocannon({
      url: testServer.baseUrl() + "/drop",
      connections: 10,
      amount: 50,
      timeout: 10,
    });
    assert.strictEqual(result.non2xx, 0, "all requests should return 2xx");
    assert.ok(result.latency.p99 < 2000, "p99 latency should be under 2s, got " + result.latency.p99 + "ms");
  });

  it("no memory leak over 200 requests", async function () {
    var autocannon = require("autocannon");
    var memBefore = process.memoryUsage().heapUsed;
    await autocannon({
      url: testServer.baseUrl() + "/auth/login",
      connections: 5,
      amount: 200,
      timeout: 10,
    });
    if (global.gc) global.gc();
    var memAfter = process.memoryUsage().heapUsed;
    var growth = memAfter - memBefore;
    assert.ok(growth < 50 * 1024 * 1024, "heap grew by " + Math.round(growth / 1024 / 1024) + "MB — possible leak");
  });
});
