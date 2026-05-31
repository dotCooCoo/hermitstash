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

// lib/rate-limit.js wraps the framework limiter: guard(opts) mounts
// b.middleware.rateLimit + the shared onDeny so every 429 is RFC 9457
// problem+json. Pin the surface + the denial shape so a regression to
// text/plain or an about:blank type is caught.
describe("rate-limit shim surface", function () {
  it("re-exports getIp delegating to client-ip", function () {
    var req = { socket: { remoteAddress: "10.0.0.1" }, headers: {} };
    assert.strictEqual(rateLimit.getIp(req), clientIp.getIp(req));
  });

  it("exposes resetAllInstances for test harnesses", function () {
    assert.strictEqual(typeof rateLimit.resetAllInstances, "function");
  });

  it("guard() returns a middleware that preserves the limiter's reset()", function () {
    var mw = rateLimit.guard({ scope: "test-guard", max: 5, windowMs: 60000, algorithm: "fixed-window" });
    assert.strictEqual(typeof mw, "function", "guard returns a middleware function");
    // routes/auth.js calls loginLimiter.reset(ip) after a successful login —
    // guard must pass the framework limiter's reset() through unchanged.
    assert.strictEqual(typeof mw.reset, "function", "guard preserves .reset(key)");
  });
  // The 429 wire shape (RFC 9457 application/problem+json) is asserted at the
  // integration level in tests/security/adversarial-resilience.test.js, where a
  // real limiter trips through the wrapped response object — the path that
  // matters, and the one a unit mock can't faithfully reproduce.
});
