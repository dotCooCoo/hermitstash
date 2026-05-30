const { describe, it } = require("node:test");
const assert = require("node:assert");

var clientIp = require("../../lib/client-ip");
var rateLimit = require("../../lib/rate-limit");

// Client-IP extraction is the trustProxy-gated read every rate-limit and audit
// path keys on. These cases pin the proxy-trust boundary: X-Forwarded-For is
// honored only when the immediate peer is a trusted proxy; otherwise the socket
// address wins, so an untrusted client can't spoof its IP via the header.
describe("client-ip getIp()", function () {
  it("returns socket IP when no X-Forwarded-For", function () {
    var req = { socket: { remoteAddress: "10.0.0.1" }, headers: {} };
    assert.strictEqual(clientIp.getIp(req), "10.0.0.1");
  });

  it("returns XFF IP when from trusted proxy (127.0.0.1)", function () {
    var req = {
      socket: { remoteAddress: "127.0.0.1" },
      headers: { "x-forwarded-for": "203.0.113.50, 70.41.3.18" },
    };
    assert.strictEqual(clientIp.getIp(req), "203.0.113.50");
  });

  it("returns socket IP when from untrusted source (ignores XFF)", function () {
    var req = {
      socket: { remoteAddress: "192.168.1.100" },
      headers: { "x-forwarded-for": "10.10.10.10" },
    };
    assert.strictEqual(clientIp.getIp(req), "192.168.1.100");
  });
});

// lib/rate-limit.js is a thin test-harness shim over the framework limiter
// (production rate-limits via b.middleware.rateLimit directly). Pin its surface
// so a future change that drops getIp / resetAllInstances is caught.
describe("rate-limit shim surface", function () {
  it("re-exports getIp delegating to client-ip", function () {
    var req = { socket: { remoteAddress: "10.0.0.1" }, headers: {} };
    assert.strictEqual(rateLimit.getIp(req), clientIp.getIp(req));
  });

  it("exposes resetAllInstances for test harnesses", function () {
    assert.strictEqual(typeof rateLimit.resetAllInstances, "function");
  });
});
