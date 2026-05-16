const { describe, it, after } = require("node:test");
const assert = require("node:assert");
var testEnv = require("../helpers/test-env");

var { isPrivateIp } = require("../../app/security/ssrf-policy");

after(function () { testEnv.cleanup(); });

describe("webhook — isPrivateIp", function () {
  // ---------------------------------------------------------------------------
  // Explicit private/reserved names
  // ---------------------------------------------------------------------------
  describe("localhost and special addresses", function () {
    it("returns true for 'localhost'", function () {
      assert.strictEqual(isPrivateIp("localhost"), true);
    });

    it("returns true for 'LOCALHOST' (case-insensitive)", function () {
      assert.strictEqual(isPrivateIp("LOCALHOST"), true);
    });

    it("returns true for 0.0.0.0", function () {
      assert.strictEqual(isPrivateIp("0.0.0.0"), true);
    });

    it("returns true for ::1 (IPv6 loopback)", function () {
      assert.strictEqual(isPrivateIp("::1"), true);
    });

    it("returns true for :: (IPv6 unspecified)", function () {
      assert.strictEqual(isPrivateIp("::"), true);
    });
  });

  // ---------------------------------------------------------------------------
  // 127.x.x.x loopback range
  // ---------------------------------------------------------------------------
  describe("127.x.x.x loopback range", function () {
    it("returns true for 127.0.0.1", function () {
      assert.strictEqual(isPrivateIp("127.0.0.1"), true);
    });

    it("returns true for 127.0.0.2", function () {
      assert.strictEqual(isPrivateIp("127.0.0.2"), true);
    });

    it("returns true for 127.255.255.255", function () {
      assert.strictEqual(isPrivateIp("127.255.255.255"), true);
    });

    it("returns true for 127.1.2.3", function () {
      assert.strictEqual(isPrivateIp("127.1.2.3"), true);
    });
  });

  // ---------------------------------------------------------------------------
  // 10.x.x.x private range
  // ---------------------------------------------------------------------------
  describe("10.x.x.x private range", function () {
    it("returns true for 10.0.0.0", function () {
      assert.strictEqual(isPrivateIp("10.0.0.0"), true);
    });

    it("returns true for 10.0.0.1", function () {
      assert.strictEqual(isPrivateIp("10.0.0.1"), true);
    });

    it("returns true for 10.255.255.255", function () {
      assert.strictEqual(isPrivateIp("10.255.255.255"), true);
    });

    it("returns true for 10.10.10.10", function () {
      assert.strictEqual(isPrivateIp("10.10.10.10"), true);
    });
  });

  // ---------------------------------------------------------------------------
  // 192.168.x.x private range
  // ---------------------------------------------------------------------------
  describe("192.168.x.x private range", function () {
    it("returns true for 192.168.0.1", function () {
      assert.strictEqual(isPrivateIp("192.168.0.1"), true);
    });

    it("returns true for 192.168.1.1", function () {
      assert.strictEqual(isPrivateIp("192.168.1.1"), true);
    });

    it("returns true for 192.168.255.255", function () {
      assert.strictEqual(isPrivateIp("192.168.255.255"), true);
    });

    it("returns false for 192.169.0.1 (outside range)", function () {
      assert.strictEqual(isPrivateIp("192.169.0.1"), false);
    });

    it("returns false for 192.167.0.1 (outside range)", function () {
      assert.strictEqual(isPrivateIp("192.167.0.1"), false);
    });
  });

  // ---------------------------------------------------------------------------
  // 169.254.x.x link-local / cloud metadata range
  // ---------------------------------------------------------------------------
  describe("169.254.x.x link-local range", function () {
    it("returns true for 169.254.0.1", function () {
      assert.strictEqual(isPrivateIp("169.254.0.1"), true);
    });

    it("returns true for 169.254.169.254 (cloud metadata)", function () {
      assert.strictEqual(isPrivateIp("169.254.169.254"), true);
    });

    it("returns true for 169.254.255.255", function () {
      assert.strictEqual(isPrivateIp("169.254.255.255"), true);
    });

    it("returns false for 169.255.0.1 (outside range)", function () {
      assert.strictEqual(isPrivateIp("169.255.0.1"), false);
    });
  });

  // ---------------------------------------------------------------------------
  // 172.16-31.x.x private range
  // ---------------------------------------------------------------------------
  describe("172.16-31.x.x private range", function () {
    it("returns true for 172.16.0.0 (start of range)", function () {
      assert.strictEqual(isPrivateIp("172.16.0.0"), true);
    });

    it("returns true for 172.16.0.1", function () {
      assert.strictEqual(isPrivateIp("172.16.0.1"), true);
    });

    it("returns true for 172.20.5.5 (middle of range)", function () {
      assert.strictEqual(isPrivateIp("172.20.5.5"), true);
    });

    it("returns true for 172.31.255.255 (end of range)", function () {
      assert.strictEqual(isPrivateIp("172.31.255.255"), true);
    });

    it("returns false for 172.15.0.1 (below range)", function () {
      assert.strictEqual(isPrivateIp("172.15.0.1"), false);
    });

    it("returns false for 172.32.0.1 (above range)", function () {
      assert.strictEqual(isPrivateIp("172.32.0.1"), false);
    });

    it("returns false for 172.100.0.1 (well above range)", function () {
      assert.strictEqual(isPrivateIp("172.100.0.1"), false);
    });
  });

  // ---------------------------------------------------------------------------
  // IPv6 private ranges (fc, fd, fe8x)
  // ---------------------------------------------------------------------------
  describe("IPv6 private ranges", function () {
    it("returns true for fc00::1 (unique local)", function () {
      assert.strictEqual(isPrivateIp("fc00::1"), true);
    });

    it("returns true for fd00::1 (unique local)", function () {
      assert.strictEqual(isPrivateIp("fd00::1"), true);
    });

    it("returns true for fd12:3456:789a::1", function () {
      assert.strictEqual(isPrivateIp("fd12:3456:789a::1"), true);
    });

    it("returns true for fe80::1 (link-local)", function () {
      assert.strictEqual(isPrivateIp("fe80::1"), true);
    });

    it("returns true for fe90::1 (link-local range)", function () {
      assert.strictEqual(isPrivateIp("fe90::1"), true);
    });

    it("returns true for fea0::1 (link-local range)", function () {
      assert.strictEqual(isPrivateIp("fea0::1"), true);
    });

    it("returns true for feb0::1 (link-local range)", function () {
      assert.strictEqual(isPrivateIp("feb0::1"), true);
    });

    it("returns true for FC00::1 (case-insensitive)", function () {
      assert.strictEqual(isPrivateIp("FC00::1"), true);
    });

    it("returns true for FD00::1 (case-insensitive)", function () {
      assert.strictEqual(isPrivateIp("FD00::1"), true);
    });

    it("returns true for FE80::1 (case-insensitive)", function () {
      assert.strictEqual(isPrivateIp("FE80::1"), true);
    });
  });

  // ---------------------------------------------------------------------------
  // ::ffff: mapped IPv4
  // ---------------------------------------------------------------------------
  describe("::ffff: mapped IPv4", function () {
    it("returns true for ::ffff:127.0.0.1 (mapped loopback)", function () {
      assert.strictEqual(isPrivateIp("::ffff:127.0.0.1"), true);
    });

    it("returns true for ::ffff:10.0.0.1 (mapped private)", function () {
      assert.strictEqual(isPrivateIp("::ffff:10.0.0.1"), true);
    });

    it("returns true for ::ffff:192.168.1.1 (mapped private)", function () {
      assert.strictEqual(isPrivateIp("::ffff:192.168.1.1"), true);
    });

    it("returns true for ::ffff:169.254.169.254 (mapped metadata)", function () {
      assert.strictEqual(isPrivateIp("::ffff:169.254.169.254"), true);
    });

    it("returns false for ::ffff:8.8.8.8 (mapped public)", function () {
      assert.strictEqual(isPrivateIp("::ffff:8.8.8.8"), false);
    });

    it("returns false for ::ffff:1.1.1.1 (mapped public)", function () {
      assert.strictEqual(isPrivateIp("::ffff:1.1.1.1"), false);
    });

    it("returns true for ::FFFF:127.0.0.1 (case-insensitive)", function () {
      assert.strictEqual(isPrivateIp("::FFFF:127.0.0.1"), true);
    });
  });

  // ---------------------------------------------------------------------------
  // Public IPs return false
  // ---------------------------------------------------------------------------
  describe("public IPs return false", function () {
    it("returns false for 8.8.8.8 (Google DNS)", function () {
      assert.strictEqual(isPrivateIp("8.8.8.8"), false);
    });

    it("returns false for 1.1.1.1 (Cloudflare DNS)", function () {
      assert.strictEqual(isPrivateIp("1.1.1.1"), false);
    });

    it("returns false for 93.184.216.34 (example.com)", function () {
      assert.strictEqual(isPrivateIp("93.184.216.34"), false);
    });

    it("returns true for 203.0.113.1 (RFC 5737 documentation range — blocked)", function () {
      assert.strictEqual(isPrivateIp("203.0.113.1"), true);
    });

    it("returns false for 54.239.28.85 (AWS public)", function () {
      assert.strictEqual(isPrivateIp("54.239.28.85"), false);
    });

    it("returns false for 2607:f8b0:4004:800::200e (public IPv6)", function () {
      assert.strictEqual(isPrivateIp("2607:f8b0:4004:800::200e"), false);
    });
  });

  // ---------------------------------------------------------------------------
  // Edge cases: bracketed IPv6, empty string
  // ---------------------------------------------------------------------------
  describe("edge cases", function () {
    it("handles bracketed IPv6 by stripping brackets", function () {
      assert.strictEqual(isPrivateIp("[::1]"), true);
    });

    it("handles bracketed public IPv6", function () {
      assert.strictEqual(isPrivateIp("[2607:f8b0:4004::200e]"), false);
    });

    it("handles bracketed private IPv6", function () {
      assert.strictEqual(isPrivateIp("[fc00::1]"), true);
    });

    it("returns true for empty string (fail closed)", function () {
      assert.strictEqual(isPrivateIp(""), true);
    });

    it("returns true (fail-closed) for random non-IP string", function () {
      // isPrivateIp expects an IP LITERAL. Non-IP input (including hostnames)
      // is treated as private/blocked — safer default. Hostname resolution
      // should go through isPrivateHost() which does DNS lookup.
      assert.strictEqual(isPrivateIp("not-an-ip"), true);
    });

    it("returns true (fail-closed) for a public domain name (not a literal IP)", function () {
      // Same rule — domain names are not IP literals. Use isPrivateHost()
      // for hostname validation (it does the DNS lookup and checks every
      // resolved address).
      assert.strictEqual(isPrivateIp("example.com"), true);
    });
  });
});
