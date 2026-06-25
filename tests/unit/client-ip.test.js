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

  it("returns the rightmost (proxy-appended) XFF IP when from a trusted proxy", function () {
    var req = {
      socket: { remoteAddress: "127.0.0.1" },
      headers: { "x-forwarded-for": "203.0.113.50, 70.41.3.18" },
    };
    // The bundled nginx appends $remote_addr, so the RIGHTMOST entry is the real
    // peer; the leftmost is client-forgeable and must NOT be trusted.
    assert.strictEqual(clientIp.getIp(req), "70.41.3.18");
  });

  it("returns socket IP when from untrusted source (ignores XFF)", function () {
    var req = {
      socket: { remoteAddress: "192.168.1.100" },
      headers: { "x-forwarded-for": "10.10.10.10" },
    };
    assert.strictEqual(clientIp.getIp(req), "192.168.1.100");
  });

  it("canonicalizes an IPv4-mapped IPv6 socket peer to its dotted-quad", function () {
    // A dual-stack listener surfaces ::ffff:1.2.3.4; folding it to 1.2.3.4 is
    // what lets a block / rate-limit on the dotted-quad also catch the peer.
    var req = { socket: { remoteAddress: "::ffff:203.0.113.5" }, headers: {} };
    assert.strictEqual(clientIp.getIp(req), "203.0.113.5");
  });
});

describe("client-ip canonicalize()", function () {
  it("folds an IPv4-mapped IPv6 address to the dotted-quad", function () {
    assert.strictEqual(clientIp.canonicalize("::ffff:1.2.3.4"), "1.2.3.4");
  });
  it("lowercases IPv6 so case variants collapse to one key", function () {
    assert.strictEqual(clientIp.canonicalize("2001:DB8::1"), "2001:db8::1");
  });
  it("leaves a plain dotted-quad unchanged", function () {
    assert.strictEqual(clientIp.canonicalize("1.2.3.4"), "1.2.3.4");
  });
  it("passes through empty / non-string input", function () {
    assert.strictEqual(clientIp.canonicalize(""), "");
    assert.strictEqual(clientIp.canonicalize(null), null);
  });
});

// Operator-configured trusted proxies now accept CIDRs (TRUST_PROXY), resolved
// through b.requestHelpers.trustedClientIp. These pin the peer-gating: an XFF is
// honored only when the immediate peer falls inside a configured range, a bare
// IP is treated as a /32, and a malformed CIDR fails safe to loopback-only —
// never throwing and never silently widening trust.
describe("client-ip operator-configured trusted proxies (CIDR)", function () {
  var config = require("../../lib/config");

  function withTrustProxy(value, fn) {
    var saved = config.trustProxy;
    config.trustProxy = value;
    try { return fn(); } finally { config.trustProxy = saved; }
  }

  it("trusts an XFF from a peer inside an operator CIDR (10.0.0.0/8)", function () {
    withTrustProxy("10.0.0.0/8", function () {
      var req = { socket: { remoteAddress: "10.1.2.3" }, headers: { "x-forwarded-for": "203.0.113.9" } };
      assert.strictEqual(clientIp.getIp(req), "203.0.113.9");
    });
  });

  it("treats a bare-IP TRUST_PROXY entry as a /32", function () {
    withTrustProxy("10.9.9.9", function () {
      var req = { socket: { remoteAddress: "10.9.9.9" }, headers: { "x-forwarded-for": "203.0.113.9" } };
      assert.strictEqual(clientIp.getIp(req), "203.0.113.9");
    });
  });

  it("ignores XFF from a peer outside the configured CIDR", function () {
    withTrustProxy("10.0.0.0/8", function () {
      var req = { socket: { remoteAddress: "192.0.2.5" }, headers: { "x-forwarded-for": "203.0.113.9" } };
      assert.strictEqual(clientIp.getIp(req), "192.0.2.5");
    });
  });

  it("fails safe to loopback-only on a malformed CIDR (never throws, never widens)", function () {
    withTrustProxy("not-a-cidr", function () {
      // loopback proxy is still trusted; an untrusted peer is still ignored.
      var loop = { socket: { remoteAddress: "127.0.0.1" }, headers: { "x-forwarded-for": "203.0.113.9" } };
      assert.strictEqual(clientIp.getIp(loop), "203.0.113.9");
      var ext = { socket: { remoteAddress: "8.8.8.8" }, headers: { "x-forwarded-for": "203.0.113.9" } };
      assert.strictEqual(clientIp.getIp(ext), "8.8.8.8");
    });
  });
});

// clientIp.rateKey is the single bucket-key transform shared by the rate-limit
// keyFn and every loginLimiter.reset() site. IPv4 stays per-host EXACT; IPv6
// collapses to its routing-significant /64 so an end-site rotating the low 64
// bits of its allocation can't mint a fresh per-IP throttle bucket per request.
describe("client-ip rateKey()", function () {
  function reqWithSocket(addr) {
    return { socket: { remoteAddress: addr }, headers: {} };
  }

  it("collapses two IPv6 addresses in the same /64 to ONE key", function () {
    var a = clientIp.rateKey(reqWithSocket("2001:db8:abcd:1234::1"));
    var b2 = clientIp.rateKey(reqWithSocket("2001:db8:abcd:1234:ffff:ffff:ffff:fffe"));
    assert.strictEqual(a, b2, "low-64-bit rotation within one /64 must share a bucket");
  });

  it("keeps two IPv6 addresses in DIFFERENT /64s on distinct keys", function () {
    var a = clientIp.rateKey(reqWithSocket("2001:db8:abcd:1234::1"));
    var b2 = clientIp.rateKey(reqWithSocket("2001:db8:abcd:5678::1"));
    assert.notStrictEqual(a, b2, "distinct /64 prefixes must not collide");
  });

  it("keeps two IPv4 hosts on distinct keys (per-host exact, no /24 masking)", function () {
    var a = clientIp.rateKey(reqWithSocket("203.0.113.10"));
    var b2 = clientIp.rateKey(reqWithSocket("203.0.113.11"));
    assert.notStrictEqual(a, b2, "IPv4 must stay per-host exact");
    assert.strictEqual(a, "203.0.113.10");
  });

  it("falls back to 'unknown' when no IP can be resolved", function () {
    assert.strictEqual(clientIp.rateKey(null), "unknown");
  });

  it("is deterministic for one request, so keyFn and reset() agree", function () {
    // routes/auth.js mounts the limiter with this default keyFn and calls
    // loginLimiter.reset(clientIp.rateKey(req)) — both must hit one bucket.
    var req = reqWithSocket("2001:db8:abcd:1234::abcd");
    assert.strictEqual(clientIp.rateKey(req), clientIp.rateKey(req));
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
    var mw = rateLimit.guard({ max: 5, windowMs: 60000, algorithm: "fixed-window" });
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
