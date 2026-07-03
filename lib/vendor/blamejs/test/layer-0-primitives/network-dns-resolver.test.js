// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * b.network.dns.resolver — validating stub resolver composing
 * b.safeDns. Tests use a fake transport so no real DoH traffic
 * leaves the box. Verifies TTL cache + serve-stale + CNAME chain
 * following + AD-bit surfacing + DNSSEC opt-in validate refusal.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

// ---- Wire-format helpers (mirror safe-dns.test.js) ----

function _hdr(id, flags, qd, an, ns, ar) {
  var h = Buffer.alloc(12);
  h.writeUInt16BE(id, 0);
  h.writeUInt16BE(flags, 2);
  h.writeUInt16BE(qd, 4);
  h.writeUInt16BE(an, 6);
  h.writeUInt16BE(ns, 8);
  h.writeUInt16BE(ar, 10);
  return h;
}

function _encName(name) {
  var labels = name.split(".").filter(Boolean);
  var parts = [];
  labels.forEach(function (l) {
    var b2 = Buffer.from(l, "ascii");
    parts.push(Buffer.from([b2.length]));
    parts.push(b2);
  });
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function _q(name, qtype) {
  var nm = _encName(name);
  var tail = Buffer.alloc(4);
  tail.writeUInt16BE(qtype, 0);
  tail.writeUInt16BE(1, 2);
  return Buffer.concat([nm, tail]);
}

function _rr(name, rtype, ttl, rdata) {
  var nm = _encName(name);
  var fixed = Buffer.alloc(10);
  fixed.writeUInt16BE(rtype, 0);
  fixed.writeUInt16BE(1, 2);
  fixed.writeUInt32BE(ttl, 4);
  fixed.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([nm, fixed, rdata]);
}

// adBit = true sets bit 5 of byte 3 (low byte of 16-bit flags at offset 2..3)
function _aRecordResponse(name, ip, ttl, adBit) {
  var octets = ip.split(".").map(function (s) { return parseInt(s, 10); });
  var rdata = Buffer.from(octets);
  var flags = 0x8180 | (adBit ? 0x0020 : 0);
  return Buffer.concat([
    _hdr(0, flags, 1, 1, 0, 0),
    _q(name, 1),
    _rr(name, 1, ttl, rdata),
  ]);
}

function _cnameResponse(name, target, ttl) {
  return Buffer.concat([
    _hdr(0, 0x8180, 1, 1, 0, 0),
    _q(name, 1),
    _rr(name, 5, ttl, _encName(target)),
  ]);
}

function _nxResponse(name) {
  // NXDOMAIN — RCODE 3 in flags; question echoed; zero answers.
  return Buffer.concat([
    _hdr(0, 0x8183, 1, 0, 0, 0),
    _q(name, 1),
  ]);
}

// ---- Fake transport ----

function _fakeTransport(map) {
  var calls = [];
  return {
    lookup: function (name, qtype) {
      var key = name.toLowerCase() + "|" + qtype;
      calls.push({ name: name, qtype: qtype });
      if (typeof map[key] === "function") return Promise.resolve(map[key]());
      if (map[key] === "__throw__") return Promise.reject(new Error("upstream-boom"));
      return Promise.resolve(map[key] || _hdr(0, 0x8180, 1, 0, 0, 0));
    },
    _calls: calls,
  };
}

// ---- Tests ----

async function testSurface() {
  check("resolver.create is fn", typeof b.network.dns.resolver.create === "function");
  var r = b.network.dns.resolver.create({ transport: _fakeTransport({}) });
  check("instance has query",        typeof r.query === "function");
  check("instance has followCnames", typeof r.followCnames === "function");
  check("instance has queryA",       typeof r.queryA === "function");
  check("instance has queryTxt",     typeof r.queryTxt === "function");
  check("instance has clearCache",   typeof r.clearCache === "function");
  check("instance has cacheSize",    typeof r.cacheSize === "function");
}

async function testResolvesAndCaches() {
  var transport = _fakeTransport({
    "example.com|1": _aRecordResponse("example.com", "192.0.2.1", 300, false),
  });
  var r = b.network.dns.resolver.create({ transport: transport });
  var r1 = await r.queryA("example.com");
  check("first call: fromCache=false",   r1.fromCache === false);
  check("first call: stale=false",       r1.stale === false);
  check("first call: rrs has A",         r1.rrs[0].decoded === "192.0.2.1");
  check("first call: ttl in ms",         r1.ttl >= 300000);
  check("first call: validated=false",   r1.validated === false);
  check("transport called once",         transport._calls.length === 1);

  var r2 = await r.queryA("example.com");
  check("second call: fromCache=true",   r2.fromCache === true);
  check("second call: stale=false",      r2.stale === false);
  check("second call: rrs same",         r2.rrs[0].decoded === "192.0.2.1");
  check("transport NOT called again",    transport._calls.length === 1);
}

async function testSingleFlightCoalescesConcurrentMisses() {
  // N concurrent queries for the same name that all miss the cache must
  // trigger ONE upstream lookup, not a thundering herd (cache stampede).
  var resp = _aRecordResponse("example.com", "192.0.2.5", 300, false);
  var calls = 0;
  // The five queries are fired synchronously (Promise.all's array is built in
  // one tick), so all four followers hit the inflight map the winner set
  // before any microtask resolves — an immediate Promise suffices; no timer
  // sleep is needed to force the overlap.
  var transport = {
    lookup: function () {
      calls += 1;
      return Promise.resolve(resp);
    },
  };
  var r = b.network.dns.resolver.create({ transport: transport });
  var results = await Promise.all([
    r.queryA("example.com"), r.queryA("example.com"), r.queryA("example.com"),
    r.queryA("example.com"), r.queryA("example.com"),
  ]);
  check("single-flight: 5 concurrent misses trigger ONE upstream lookup", calls === 1);
  check("single-flight: all 5 callers receive the answer",
    results.every(function (x) { return x.rrs[0].decoded === "192.0.2.5"; }));
}

async function testValidateOptInRefusesAdZero() {
  var transport = _fakeTransport({
    "example.com|1": _aRecordResponse("example.com", "192.0.2.1", 300, false),
  });
  var r = b.network.dns.resolver.create({ transport: transport });
  var threw = null;
  try { await r.queryA("example.com", { validate: true }); }
  catch (e) { threw = e; }
  check("validate=true with AD=0 refused", threw && threw.code === "resolver/validate-failed");
}

async function testValidateOptInRefusesCachedAdZero() {
  // PR #58 Codex P1: a cache warmed by a non-validating call must not
  // serve to a later validate: true caller. The verdict (AD bit) is
  // per-response (RFC 4035 §3.2.3), so the cached entry's stored
  // `validated: false` must trip the validate-failed throw.
  var transport = _fakeTransport({
    "example.com|1": _aRecordResponse("example.com", "192.0.2.1", 300, false),
  });
  var r = b.network.dns.resolver.create({ transport: transport });
  await r.queryA("example.com");                   // warm cache (no validate)
  check("first call: cache size 1", r.cacheSize() === 1);
  var threw = null;
  try { await r.queryA("example.com", { validate: true }); }
  catch (e) { threw = e; }
  check("validate=true on cached AD=0 refused (cache-bypass defense)",
    threw && threw.code === "resolver/validate-failed");
}

async function testValidateOptInAcceptsAdOne() {
  var transport = _fakeTransport({
    "example.com|1": _aRecordResponse("example.com", "192.0.2.1", 300, true),
  });
  var r = b.network.dns.resolver.create({ transport: transport });
  var got = await r.queryA("example.com", { validate: true });
  check("validate=true with AD=1 succeeds", got.rrs[0].decoded === "192.0.2.1");
  check("validate=true sets validated=true", got.validated === true);
}

async function testFollowsCnameChain() {
  var transport = _fakeTransport({
    "alias.example.com|1": _cnameResponse("alias.example.com", "real.example.com", 300),
    "real.example.com|1":  _aRecordResponse("real.example.com", "192.0.2.5", 300, false),
  });
  var r = b.network.dns.resolver.create({ transport: transport });
  var got = await r.followCnames("alias.example.com", "A");
  check("followCnames: chain length 2",   got.chain.length === 2);
  check("followCnames: chain start",      got.chain[0] === "alias.example.com");
  check("followCnames: chain end",        got.chain[1] === "real.example.com");
  check("followCnames: rr.decoded",       got.rrs[0].decoded === "192.0.2.5");
}

async function testCnameChainCap() {
  // Build a chain longer than the strict cap (8). Each hop CNAMEs to the next.
  var map = {};
  for (var i = 0; i < 20; i += 1) {
    var from = "h" + i + ".example.com";
    var to   = "h" + (i + 1) + ".example.com";
    map[from + "|1"] = _cnameResponse(from, to, 300);
  }
  var transport = _fakeTransport(map);
  var r = b.network.dns.resolver.create({ transport: transport });
  var threw = null;
  try { await r.followCnames("h0.example.com", "A"); }
  catch (e) { threw = e; }
  check("CNAME chain cap throws",  threw !== null);
  check("CNAME chain cap code",    threw && threw.code === "safe-dns/oversize-cname-depth");
}

async function testServeStaleOnUpstreamFailure() {
  // First call succeeds; second call fails; should serve stale.
  var callCount = 0;
  var transport = {
    _calls: [],
    lookup: function (name, qtype) {
      transport._calls.push({ name: name, qtype: qtype });
      callCount += 1;
      if (callCount === 1) {
        return Promise.resolve(_aRecordResponse("example.com", "192.0.2.1", 1, false));
      }
      return Promise.reject(new Error("upstream-down"));
    },
  };
  var r = b.network.dns.resolver.create({
    transport:  transport,
    minTtlMs:   1,
    maxTtlMs:   20,
    serveStale: 60000,
  });
  var r1 = await r.queryA("example.com");
  check("first call returns",          r1.rrs[0].decoded === "192.0.2.1");

  // Wait for the maxTtlMs=20 cache entry to expire.
  await helpers.passiveObserve(80, "dns-resolver: cache TTL elapsed for serve-stale test");

  var r2 = await r.queryA("example.com");
  check("serve-stale on failure",      r2.rrs[0].decoded === "192.0.2.1");
  check("serve-stale marks stale=true", r2.stale === true);
  check("serve-stale marks fromCache=true", r2.fromCache === true);
}

async function testServeStaleDisabled() {
  // With serveStale: false, upstream failure throws even with cache.
  var callCount = 0;
  var transport = {
    _calls: [],
    lookup: function (name, qtype) {
      callCount += 1;
      if (callCount === 1) return Promise.resolve(_aRecordResponse("example.com", "192.0.2.1", 1, false));
      return Promise.reject(new Error("upstream-down"));
    },
  };
  var r = b.network.dns.resolver.create({
    transport:  transport,
    minTtlMs:   1,
    maxTtlMs:   20,
    serveStale: false,
  });
  await r.queryA("example.com");
  // Wait for the maxTtlMs=20 cache entry to expire so the second call
  // misses the cache and hits the failing upstream.
  await helpers.passiveObserve(80, "dns-resolver: cache TTL elapsed for serveStale-false test");
  var threw = null;
  try { await r.queryA("example.com"); }
  catch (e) { threw = e; }
  check("serveStale=false: upstream-failed surfaces", threw && threw.code === "resolver/upstream-failed");
}

async function testNxdomainRefused() {
  var transport = _fakeTransport({
    "nx.example.com|1": _nxResponse("nx.example.com"),
  });
  var r = b.network.dns.resolver.create({ transport: transport });
  var threw = null;
  try { await r.queryA("nx.example.com"); }
  catch (e) { threw = e; }
  check("NXDOMAIN surfaces as error",  threw && threw.code === "resolver/nxdomain-or-error");
}

async function testBadInput() {
  var r = b.network.dns.resolver.create({ transport: _fakeTransport({}) });
  var threw = null;
  try { await r.query("", "A"); }
  catch (e) { threw = e; }
  check("empty name refused", threw && threw.code === "resolver/bad-input");

  var threw2 = null;
  try { await r.query("example.com", "BOGUS"); }
  catch (e) { threw2 = e; }
  check("unknown qtype refused", threw2 && threw2.code === "resolver/bad-input");
}

async function testProfileResolution() {
  var r = b.network.dns.resolver.create({ transport: _fakeTransport({}), profile: "balanced" });
  check("profile balanced", r.profile === "balanced");

  var threw = null;
  try { b.network.dns.resolver.create({ transport: _fakeTransport({}), profile: "lax" }); }
  catch (e) { threw = e; }
  check("bad profile refused", threw && threw.code === "resolver/bad-profile");
}

async function testPostureResolvesToStrict() {
  var r = b.network.dns.resolver.create({ transport: _fakeTransport({}), posture: "hipaa" });
  check("posture hipaa → strict", r.profile === "strict");
}

async function testBadTransport() {
  var threw = null;
  try { b.network.dns.resolver.create({ transport: {} }); }
  catch (e) { threw = e; }
  check("missing lookup refused", threw && threw.code === "resolver/bad-transport");
}

async function testClearCache() {
  var transport = _fakeTransport({
    "example.com|1": _aRecordResponse("example.com", "192.0.2.1", 300, false),
  });
  var r = b.network.dns.resolver.create({ transport: transport });
  await r.queryA("example.com");
  check("cache size 1", r.cacheSize() === 1);
  r.clearCache();
  check("cache size 0 after clear", r.cacheSize() === 0);
  await r.queryA("example.com");
  check("re-fetched after clear", transport._calls.length === 2);
}

async function testTtlCapping() {
  // Upstream returns TTL=999999 seconds; resolver should clamp to maxTtlMs.
  var transport = _fakeTransport({
    "example.com|1": _aRecordResponse("example.com", "192.0.2.1", 999999, false),
  });
  var r = b.network.dns.resolver.create({
    transport: transport,
    maxTtlMs:  5000,
    minTtlMs:  100,
  });
  var got = await r.queryA("example.com");
  check("TTL clamped to maxTtlMs", got.ttl <= 5000);
}

async function testTtlFloor() {
  // Upstream returns TTL=1 second; resolver should floor to minTtlMs.
  var transport = _fakeTransport({
    "example.com|1": _aRecordResponse("example.com", "192.0.2.1", 1, false),
  });
  var r = b.network.dns.resolver.create({
    transport: transport,
    minTtlMs:  30000,
  });
  var got = await r.queryA("example.com");
  check("TTL floored to minTtlMs", got.ttl >= 30000);
}

async function run() {
  await testSurface();
  await testResolvesAndCaches();
  await testSingleFlightCoalescesConcurrentMisses();
  await testValidateOptInRefusesAdZero();
  await testValidateOptInAcceptsAdOne();
  await testValidateOptInRefusesCachedAdZero();
  await testFollowsCnameChain();
  await testCnameChainCap();
  await testServeStaleOnUpstreamFailure();
  await testServeStaleDisabled();
  await testNxdomainRefused();
  await testBadInput();
  await testProfileResolution();
  await testPostureResolvesToStrict();
  await testBadTransport();
  await testClearCache();
  await testTtlCapping();
  await testTtlFloor();
}

module.exports = { run: run };

if (require.main === module) run().catch(function (e) {
  process.stderr.write("FAIL: " + (e && e.stack || e) + "\n");
  process.exit(1);
});
