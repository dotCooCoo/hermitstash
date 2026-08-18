"use strict";

/**
 * Operator CIDR lists are validated per entry, and one bad entry costs only itself.
 *
 * Two lists take operator-written CIDRs: TRUST_PROXY, which decides whose
 * X-Forwarded-For is believed, and ADMIN_ALLOWED_CIDRS, which fences /admin to a
 * network. Neither was really checking its entries.
 *
 * The trust list handed the whole thing to trustedClientIp, which throws on the
 * first bad entry, and the catch dropped the deployment to loopback-only. Behind
 * a reverse proxy that means every client resolves to the proxy's own address:
 * per-IP rate limits and IP blocks collapse onto one bucket, and the admin fence
 * reads that same address, so it admits any caller as soon as the operator's
 * allowlist covers the proxy's network. One typo, and a fence meant for the
 * internal network is open to everyone reaching the proxy.
 *
 * The fence validated entries with ssrfGuard.cidrContains inside a try/catch,
 * but that helper answers false for an unparseable range rather than throwing,
 * so the check never rejected anything.
 */

require("../helpers/isolate-db"); // must precede every HermitStash require
var { describe, it } = require("node:test");
var assert = require("node:assert");
var path = require("node:path");
var fs = require("node:fs");
var b = require("../../lib/vendor/blamejs");
var clientIp = require("../../lib/client-ip");

describe("operator CIDR lists are validated per entry", function () {
  it("keeps the good entries when one is malformed", function () {
    // The whole point. Previously the first bad entry threw and every other
    // entry went with it.
    var parsed = clientIp.parseCidrList("10.0.0.0/8, not-a-cidr, 192.168.1.0/24");
    assert.deepEqual(parsed.valid, ["10.0.0.0/8", "192.168.1.0/24"],
      "a malformed entry must cost only itself");
    assert.equal(parsed.invalid.length, 1);
    assert.equal(parsed.invalid[0].entry, "not-a-cidr");
    assert.ok(parsed.invalid[0].reason, "a rejected entry must say why, so the log line is useful");
  });

  it("gives a bare address the mask it needs", function () {
    // Written without one it matched nothing at all — not even itself — so an
    // operator who fenced /admin to their own address was locked out silently.
    assert.equal(b.ssrfGuard.cidrContains("203.0.113.5", "203.0.113.5"), false,
      "precondition: a bare address matches nothing, which is why it must be normalised");
    assert.deepEqual(clientIp.parseCidrList("203.0.113.5").valid, ["203.0.113.5/32"]);
    assert.deepEqual(clientIp.parseCidrList("2001:db8::1").valid, ["2001:db8::1/128"]);
    assert.equal(b.ssrfGuard.cidrContains("203.0.113.5/32", "203.0.113.5"), true,
      "and the normalised form must match the address the operator named");
  });

  it("accepts the ranges these two settings actually get set to", function () {
    // A validator that refuses private ranges is useless here: a trusted proxy
    // sits on the LAN and an admin fence names the internal network. The guard's
    // own defaults refuse all of these, which is why the policies are explicit.
    ["127.0.0.1/32", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.1.0/24",
      "fd00::/8", "203.0.113.0/24", "2001:db8::/32"].forEach(function (cidr) {
      assert.deepEqual(clientIp.parseCidrList(cidr).valid, [cidr],
        cidr + " is an ordinary operator entry and must be accepted");
    });
  });

  it("still accepts a range written with host bits set", function () {
    // 10.0.0.1/8 is a common way of writing 10.0.0.0/8. Both consumers mask the
    // host bits identically, so it already behaves as the operator intends —
    // refusing it would break a deployment that works today.
    assert.deepEqual(clientIp.parseCidrList("10.0.0.1/8").valid, ["10.0.0.1/8"]);
    assert.equal(b.ssrfGuard.cidrContains("10.0.0.1/8", "10.5.5.5"), true,
      "and it must keep matching the range the operator meant");
  });

  it("rejects the shapes that silently matched nothing", function () {
    // The last entry carries a real U+202E, built from its number rather than
    // typed: identical bytes for the parser, but an unterminated override in the
    // source reorders the remainder of this line for anyone reading it.
    var RLO = String.fromCodePoint(0x202E);   // RIGHT-TO-LEFT OVERRIDE
    ["true", "yes", "not-a-cidr", "999.1.1.1/32", "10.0.0.0/99", "10.0.0.0/-1", "10.0.0.0/8" + RLO]
      .forEach(function (entry) {
        var parsed = clientIp.parseCidrList(entry);
        assert.equal(parsed.valid.length, 0, JSON.stringify(entry) + " must not be treated as a range");
        assert.equal(parsed.invalid.length, 1);
      });
  });

  it("the old check could not have caught any of them", function () {
    // Pinned so that a future refactor back to cidrContains-in-a-try/catch shows
    // up as a failure rather than as a check that quietly passes everything.
    ["true", "not-a-cidr", "999.1.1.1/32", "10.0.0.0/99"].forEach(function (entry) {
      assert.doesNotThrow(function () { b.ssrfGuard.cidrContains(entry, "127.0.0.1"); },
        "cidrContains answers false for " + JSON.stringify(entry) + " rather than throwing, so a "
        + "try/catch around it rejects nothing");
    });
  });

  it("anything it accepts, the resolver will actually build", function () {
    // The cross-check that matters: if the guard passed an entry the resolver
    // then refused, the list would still collapse to loopback-only and the fix
    // would be worth nothing.
    var accepted = clientIp.parseCidrList(
      "10.0.0.0/8, 192.168.1.0/24, 10.0.0.1/8, 203.0.113.5, ::1/128, 2001:db8::/32, fd00::/8").valid;
    assert.ok(accepted.length >= 7);
    assert.doesNotThrow(function () {
      b.requestHelpers.trustedClientIp({ trustedProxies: accepted });
    }, "every entry the guard accepts must be one trustedClientIp can build from");
  });

  it("an empty or absent setting is not an error", function () {
    [undefined, null, "", "   ", ",,"].forEach(function (v) {
      var parsed = clientIp.parseCidrList(v);
      assert.deepEqual(parsed.valid, []);
      assert.deepEqual(parsed.invalid, []);
    });
  });

  it("reports a rejected entry once per config change, not once per request", function () {
    // getIp runs on essentially every request — through authentication, rate
    // limiting and the audit trail. Parsing and reporting have to sit behind the
    // resolver's cache: in front of it, one persistent typo revalidates every
    // entry and writes a log line on every single request.
    var config = require("../../lib/config");
    var original = config.trustProxy;
    var errors = [];
    var realError = console.error;
    console.error = function (msg) { errors.push(String(msg)); };
    try {
      config.trustProxy = "10.0.0.0/8, not-a-cidr";
      var req = { socket: { remoteAddress: "10.1.2.3" }, headers: {} };
      for (var i = 0; i < 25; i++) clientIp.getIp(req);
      var mine = errors.filter(function (e) { return e.indexOf("TRUST_PROXY entry ignored") !== -1; });
      assert.equal(mine.length, 1, "expected one notice across 25 calls, got " + mine.length);
      assert.match(mine[0], /not-a-cidr/, "and it must name the entry that was dropped");

      // A change that swaps WHICH entry is bad leaves the surviving list
      // identical, so it has to be noticed by the raw value rather than by the
      // parsed result.
      config.trustProxy = "10.0.0.0/8, also-not-a-cidr";
      clientIp.getIp(req);
      assert.equal(errors.filter(function (e) { return e.indexOf("also-not-a-cidr") !== -1; }).length, 1,
        "a config edit that only changes which entry is malformed must still be reported");
    } finally {
      console.error = realError;
      config.trustProxy = original;
    }
  });

  it("the trust list drops bad entries and the admin fence refuses to boot on them", function () {
    // Deliberately different: TRUST_PROXY is re-read on config reload, so a bad
    // value pushed to a running server must not stop it serving. The admin fence
    // is read once at boot, where a broken entry is an operator emergency.
    var ip = fs.readFileSync(path.join(__dirname, "..", "..", "lib", "client-ip.js"), "utf8");
    assert.match(ip, /parseCidrList\(raw\)/, "the trust list must go through the parser");
    // Which makes the parser itself the thing that must not throw, whatever a
    // config file happens to contain. The NUL is built from its number for the
    // same reason as the override above: typed literally it makes ripgrep treat
    // this entire file as binary, and every grep-based gate then skips it in
    // silence.
    var NUL = String.fromCharCode(0);
    [undefined, null, 0, 123, true, {}, [], NUL, "a".repeat(4096), "10.0.0.0/8,".repeat(500)]
      .forEach(function (v) {
        assert.doesNotThrow(function () { clientIp.parseCidrList(v); },
          "parsing " + JSON.stringify(v === undefined ? "undefined" : v).slice(0, 40) + " must not throw");
      });

    // The contrast, asserted on behaviour rather than on the text of whichever
    // file currently holds the fence. Same bad entry: the trust list drops it
    // and keeps the rest, the fence refuses outright.
    var adminFence = require("../../app/security/admin-fence");
    assert.deepStrictEqual(clientIp.parseCidrList("10.0.0.0/8,not-a-cidr").valid.length, 1,
      "the trust list keeps the good entry");
    assert.throws(function () { adminFence.compile(["10.0.0.0/8", "not-a-cidr"]); },
      /ADMIN_ALLOWED_CIDRS contains a malformed entry/,
      "the fence refuses to build on one, which is what its comment always claimed");
  });
});
