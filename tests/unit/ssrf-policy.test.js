const { describe, it, mock } = require("node:test");
const assert = require("node:assert");
const dns = require("node:dns");
const b = require("../../lib/vendor/blamejs");

var { isPrivateIp, isPrivateHost, validateOutboundUrl } = require("../../app/security/ssrf-policy");

// The primitive isPrivateIp delegates to. Pins the exact classify contract
// the wrapper is built on — most importantly that classify returns null for
// a public address AND for non-IP input, which is why isPrivateIp layers a
// fail-closed default on top before trusting classify's verdict.
describe("ssrf-policy — b.ssrfGuard.classify contract", function () {
  it("returns null for a routable public IP", function () {
    assert.strictEqual(b.ssrfGuard.classify("8.8.8.8"), null);
  });
  it("classifies the reserved 240/4 block (250.1.2.3 → 'reserved')", function () {
    assert.strictEqual(b.ssrfGuard.classify("250.1.2.3"), "reserved");
  });
  it("classifies the ECS metadata IP (169.254.170.2 → 'cloud-metadata')", function () {
    assert.strictEqual(b.ssrfGuard.classify("169.254.170.2"), "cloud-metadata");
  });
  it("returns null (not blocked) for non-IP input — isPrivateIp adds fail-closed itself", function () {
    assert.strictEqual(b.ssrfGuard.classify("not-an-ip"), null);
  });
});

// Complements tests/unit/webhook.test.js (which exhaustively covers the
// isPrivateIp basics — 127/8, 10/8, 172.16/12, 192.168/16, 169.254/16,
// IPv6 ULA / link-local, ::ffff: mapped, public IPs). This file locks the
// ranges that the hand-rolled net.BlockList covered but were never tested,
// the v6-transition reclassification, and the isPrivateHost /
// validateOutboundUrl surfaces that had no direct coverage.

describe("ssrf-policy — isPrivateIp reserved-range coverage", function () {
  describe("CGNAT 100.64.0.0/10 (RFC 6598)", function () {
    it("blocks 100.64.0.1 (start)", function () { assert.strictEqual(isPrivateIp("100.64.0.1"), true); });
    it("blocks 100.127.255.255 (end)", function () { assert.strictEqual(isPrivateIp("100.127.255.255"), true); });
    it("allows 100.63.255.255 (just below)", function () { assert.strictEqual(isPrivateIp("100.63.255.255"), false); });
    it("allows 100.128.0.1 (just above)", function () { assert.strictEqual(isPrivateIp("100.128.0.1"), false); });
  });

  describe("benchmarking 198.18.0.0/15 (RFC 2544)", function () {
    it("blocks 198.18.0.1", function () { assert.strictEqual(isPrivateIp("198.18.0.1"), true); });
    it("blocks 198.19.255.255 (end of /15)", function () { assert.strictEqual(isPrivateIp("198.19.255.255"), true); });
    it("allows 198.17.255.255 (just below)", function () { assert.strictEqual(isPrivateIp("198.17.255.255"), false); });
    it("allows 198.20.0.1 (just above)", function () { assert.strictEqual(isPrivateIp("198.20.0.1"), false); });
  });

  describe("documentation / protocol nets", function () {
    it("blocks 192.0.0.1 (IETF protocol, 192.0.0/24)", function () { assert.strictEqual(isPrivateIp("192.0.0.1"), true); });
    it("blocks 192.0.2.1 (TEST-NET-1)", function () { assert.strictEqual(isPrivateIp("192.0.2.1"), true); });
    it("blocks 198.51.100.1 (TEST-NET-2)", function () { assert.strictEqual(isPrivateIp("198.51.100.1"), true); });
    it("allows 192.0.3.1 (outside the /24 doc blocks)", function () { assert.strictEqual(isPrivateIp("192.0.3.1"), false); });
  });

  describe("multicast 224.0.0.0/4", function () {
    it("blocks 224.0.0.1 (start)", function () { assert.strictEqual(isPrivateIp("224.0.0.1"), true); });
    it("blocks 239.255.255.255 (end)", function () { assert.strictEqual(isPrivateIp("239.255.255.255"), true); });
    it("allows 223.255.255.255 (just below multicast)", function () { assert.strictEqual(isPrivateIp("223.255.255.255"), false); });
  });

  describe("reserved 240.0.0.0/4 — the range the old prefix-string check missed", function () {
    it("blocks 240.0.0.1 (start)", function () { assert.strictEqual(isPrivateIp("240.0.0.1"), true); });
    it("blocks 250.1.2.3 (mid 240/4 — silently public under the old '240.' string check)", function () {
      assert.strictEqual(isPrivateIp("250.1.2.3"), true);
    });
    it("blocks 255.255.255.255 (limited broadcast)", function () { assert.strictEqual(isPrivateIp("255.255.255.255"), true); });
  });

  describe("cloud-metadata IPs", function () {
    it("blocks 169.254.169.254 (AWS/GCP/Azure IMDS)", function () { assert.strictEqual(isPrivateIp("169.254.169.254"), true); });
    it("blocks 169.254.170.2 (AWS ECS task-role)", function () { assert.strictEqual(isPrivateIp("169.254.170.2"), true); });
    it("blocks fd00:ec2::254 (IMDS over IPv6)", function () { assert.strictEqual(isPrivateIp("fd00:ec2::254"), true); });
  });

  describe("IPv6 reserved prefixes", function () {
    it("blocks ff02::1 (multicast)", function () { assert.strictEqual(isPrivateIp("ff02::1"), true); });
    it("blocks 100::1 (discard, RFC 6666)", function () { assert.strictEqual(isPrivateIp("100::1"), true); });
    it("blocks 2001:db8::1 (documentation)", function () { assert.strictEqual(isPrivateIp("2001:db8::1"), true); });
  });

  describe("v6-transition wrappers reclassify the embedded v4", function () {
    it("blocks NAT64 64:ff9b::1 (embedded v4 in 0/8 reserved)", function () { assert.strictEqual(isPrivateIp("64:ff9b::1"), true); });
    it("blocks NAT64 wrapping a public v4 (refused wholesale)", function () { assert.strictEqual(isPrivateIp("64:ff9b::808:808"), true); });
    it("blocks NAT64 wrapping RFC-1918 192.168.0.1 (64:ff9b::c0a8:1)", function () { assert.strictEqual(isPrivateIp("64:ff9b::c0a8:1"), true); });
    it("blocks 6to4 2002::1 (embedded v4 reserved)", function () { assert.strictEqual(isPrivateIp("2002::1"), true); });
    it("blocks 6to4 wrapping loopback (2002:7f00:1::)", function () { assert.strictEqual(isPrivateIp("2002:7f00:1::"), true); });
    it("blocks 6to4 wrapping RFC-1918 10.0.0.1 (2002:a00:1::)", function () { assert.strictEqual(isPrivateIp("2002:a00:1::"), true); });
  });

  describe("IPv6 link-local fe80::/10 boundary", function () {
    it("blocks febf::1 (last address in the /10)", function () { assert.strictEqual(isPrivateIp("febf::1"), true); });
    it("allows fec0::1 (first address past the /10)", function () { assert.strictEqual(isPrivateIp("fec0::1"), false); });
  });
});

describe("ssrf-policy — isPrivateHost", function () {
  it("blocks a literal private IP without DNS", async function () {
    assert.deepStrictEqual(await isPrivateHost("10.0.0.1"), { blocked: true });
  });

  it("does not block a literal public IP", async function () {
    assert.deepStrictEqual(await isPrivateHost("8.8.8.8"), { blocked: false });
  });

  it("blocks the metadata.google.internal name (pre-DNS denylist)", async function () {
    assert.deepStrictEqual(await isPrivateHost("metadata.google.internal"), { blocked: true });
  });

  it("blocks the bare 'metadata' name", async function () {
    assert.deepStrictEqual(await isPrivateHost("metadata"), { blocked: true });
  });

  it("blocks 'metadata.google' (denylist entry)", async function () {
    assert.deepStrictEqual(await isPrivateHost("metadata.google"), { blocked: true });
  });

  it("blocks the literal 169.254.169.254 (denylist + link-local)", async function () {
    assert.deepStrictEqual(await isPrivateHost("169.254.169.254"), { blocked: true });
  });

  it("blocks the literal fd00:ec2::254 (denylist + IMDS-over-IPv6)", async function () {
    assert.deepStrictEqual(await isPrivateHost("fd00:ec2::254"), { blocked: true });
  });

  it("blocks empty / missing hostname (fail closed)", async function () {
    assert.deepStrictEqual(await isPrivateHost(""), { blocked: true });
  });

  it("resolves 'localhost' and blocks it (every resolved address is loopback)", async function () {
    const result = await isPrivateHost("localhost");
    assert.strictEqual(result.blocked, true);
  });

  it("blocks if ANY resolved address is private (DNS-rebinding defence)", async function () {
    mock.method(dns, "lookup", function (host, opts, cb) {
      // One public + one private — the presence of a single internal
      // address must refuse the whole host.
      cb(null, [{ address: "93.184.216.34", family: 4 }, { address: "10.1.2.3", family: 4 }]);
    });
    try {
      assert.deepStrictEqual(await isPrivateHost("rebind.example"), { blocked: true });
    } finally {
      mock.restoreAll();
    }
  });

  it("returns the pinned address + family on a clean public resolve (TOCTOU contract)", async function () {
    mock.method(dns, "lookup", function (host, opts, cb) {
      cb(null, [{ address: "93.184.216.34", family: 4 }]);
    });
    try {
      assert.deepStrictEqual(
        await isPrivateHost("public.example"),
        { blocked: false, address: "93.184.216.34", family: 4 }
      );
    } finally {
      mock.restoreAll();
    }
  });

  it("carries family:6 through on a clean public IPv6 resolve (pin contract)", async function () {
    mock.method(dns, "lookup", function (host, opts, cb) {
      cb(null, [{ address: "2606:4700:4700::1111", family: 6 }]);
    });
    try {
      assert.deepStrictEqual(
        await isPrivateHost("public6.example"),
        { blocked: false, address: "2606:4700:4700::1111", family: 6 }
      );
    } finally {
      mock.restoreAll();
    }
  });

  it("blocks a hostname that resolves to the ECS metadata IP (169.254.170.2 — not in the name denylist)", async function () {
    mock.method(dns, "lookup", function (host, opts, cb) {
      cb(null, [{ address: "169.254.170.2", family: 4 }]);
    });
    try {
      assert.deepStrictEqual(await isPrivateHost("ecs-rebind.example"), { blocked: true });
    } finally {
      mock.restoreAll();
    }
  });

  it("blocks when DNS resolution fails (fail closed)", async function () {
    mock.method(dns, "lookup", function (host, opts, cb) { cb(new Error("ENOTFOUND")); });
    try {
      assert.deepStrictEqual(await isPrivateHost("nxdomain.example"), { blocked: true });
    } finally {
      mock.restoreAll();
    }
  });
});

describe("ssrf-policy — validateOutboundUrl", function () {
  it("accepts an https URL and returns the parsed URL", function () {
    const r = validateOutboundUrl("https://hooks.example.com/path");
    assert.strictEqual(r.valid, true);
    assert.strictEqual(r.url.hostname, "hooks.example.com");
  });

  it("rejects a cleartext http URL (HTTPS-only)", function () {
    assert.strictEqual(validateOutboundUrl("http://hooks.example.com/path").valid, false);
  });

  it("rejects a non-http(s) scheme", function () {
    assert.strictEqual(validateOutboundUrl("ftp://files.example.com/x").valid, false);
  });

  it("rejects embedded credentials", function () {
    // b.safeUrl.parse refuses userinfo at parse time, so the URL is rejected
    // there ("Invalid URL"); the explicit username/password guard in
    // validateOutboundUrl stands behind it as defence-in-depth. Either way
    // a credentialed URL is refused.
    assert.strictEqual(validateOutboundUrl("https://user:pass@hooks.example.com/path").valid, false);
  });

  it("rejects a malformed URL", function () {
    assert.strictEqual(validateOutboundUrl("not a url").valid, false);
  });
});
