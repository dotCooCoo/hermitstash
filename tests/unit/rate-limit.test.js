const { describe, it } = require("node:test");
const assert = require("node:assert");

var clientIp = require("../../lib/client-ip");
var rateLimit = require("../../lib/rate-limit");

describe("rate-limit", function () {
  describe("check()", function () {
    it("returns allowed when key is null", function () {
      var result = rateLimit.check("test-null", null, 5, 60000);
      assert.strictEqual(result.allowed, true);
      assert.strictEqual(result.remaining, 5);
      assert.strictEqual(result.retryAfter, 0);
    });

    it("blocks after exceeding max attempts", function () {
      var action = "test-block-" + Date.now();
      for (var i = 0; i < 3; i++) {
        var r = rateLimit.check(action, "1.2.3.4", 3, 60000);
        assert.strictEqual(r.allowed, true, "attempt " + (i + 1) + " should be allowed");
      }
      var blocked = rateLimit.check(action, "1.2.3.4", 3, 60000);
      assert.strictEqual(blocked.allowed, false);
      assert.strictEqual(blocked.remaining, 0);
      assert.ok(blocked.retryAfter > 0, "retryAfter should be positive");
    });

    it("resets counter after window expires", function (_, done) {
      var action = "test-expire-" + Date.now();
      rateLimit.check(action, "2.3.4.5", 1, 50);
      var blocked = rateLimit.check(action, "2.3.4.5", 1, 50);
      assert.strictEqual(blocked.allowed, false, "should be blocked before window expires");
      setTimeout(function () {
        var after = rateLimit.check(action, "2.3.4.5", 1, 50);
        assert.strictEqual(after.allowed, true, "should be allowed after window expires");
        done();
      }, 80);
    });
  });

  describe("reset()", function () {
    it("clears the counter for a key", function () {
      var action = "test-reset-" + Date.now();
      rateLimit.check(action, "5.6.7.8", 1, 60000);
      var blocked = rateLimit.check(action, "5.6.7.8", 1, 60000);
      assert.strictEqual(blocked.allowed, false);
      rateLimit.reset(action, "5.6.7.8");
      var after = rateLimit.check(action, "5.6.7.8", 1, 60000);
      assert.strictEqual(after.allowed, true, "should be allowed after reset");
    });
  });

  describe("getIp()", function () {
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
});
